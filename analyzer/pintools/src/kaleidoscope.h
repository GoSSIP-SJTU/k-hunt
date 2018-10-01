extern ConfigReader Config;

static FileManager FpCodePool("./data/bblInst.log", "w");
static FileManager ICFlogFile("./data/icf.log", "w");
static FileManager Logger("./data/kscope.log", "w");
static FileManager kThread("./data/ksThreads.log", "w");
static FileManager iCounter("./data/instCounter.log", "w");

static Compressor KsTrace;
static Compressor KsMemReadTrace;
static Compressor KsMemWriteTrace;

static map<ADDRINT, size_t> InstCounter;
static size_t InstRecordThreshold = 0x40;
/*
 * The lock for I/O.
 */
static PIN_LOCK fileLock;

static const int MaxThreads = 256;
static size_t ThreadUid[MaxThreads]; // index every instructions
static unsigned char ThreadIDs[256] = {0};
static MemOP WriteBuffer; // put this into stack for multi threads!
static std::map<ADDRINT, std::string> Addr2str;

/* ================================================================== */
// Global variables 
/* ================================================================== */

static UINT64 insCount = 0;        //number of dynamically executed instructions
static UINT64 bblCount = 0;        //number of dynamically executed basic blocks


class Switch
{
public:
	Switch() : sw(false) {}

	void set_sw( bool s )
	{
		sw = s;
	}

	bool is_on()
	{
		return sw;
	}
private:
	bool sw;
};

static Switch swtch;


/* ===================================================================== */
// Analysis routines
/* ===================================================================== */
static VOID log_ICF(ADDRINT pc, ADDRINT target)
{
	//cout << "*************" << hex << pc << "***************" << endl;
	if (Addr2str.find(pc) != Addr2str.end())
		fprintf( ICFlogFile.fp(), "[%08x -> %08x] %s#%d\n", pc, target, Addr2str[pc].c_str(), ( PIN_ThreadId() & 0xFFFF ));
	else
		fprintf( ICFlogFile.fp(), "unknown pc %08x\n", pc);

	fflush( ICFlogFile.fp() );
}


// Pin calls this function every time a new basic block is encountered
// It inserts a call to docount
static VOID bbl_trace(TRACE trace, VOID *v)
{
	// Visit every basic block in the trace
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
		// Insert a call to docount for every bbl, passing the number of instructions.
        // IPOINT_ANYWHERE allows Pin to schedule the call anywhere in the bbl to obtain best performance.
        // Use a fast linkage for the call.
		ADDRINT pc = BBL_Address(bbl);

		if ( pc >= Config.getCodeStartAddr() && pc <= Config.getCodeEndAddr() )
		{
			for ( INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
			{
				// init instruction recording counter
				InstCounter[INS_Address (ins)] = 0;

				fprintf( FpCodePool.fp(), "%08x|%s\n", INS_Address (ins), INS_Disassemble(ins).c_str() );
			}
			fprintf( FpCodePool.fp(), "----\n" );
		}
	}
}


// Record a memory read record
static VOID rec_mem_read( ADDRINT pc, VOID * addr, UINT32 len )
{
	if ( InstCounter[pc] > InstRecordThreshold || !swtch.is_on() )
		return;


	if ( len > 4 ) // ignore this one!
		return;

	static MemOP ReadBuffer;
	ReadBuffer.len = len;
	ReadBuffer.tid = ( PIN_ThreadId() & 0xFFFF );
	ReadBuffer.addr = addr;
	ReadBuffer.type = 'R';
	ReadBuffer.uid = ThreadUid[ReadBuffer.tid];

	if ( len == 1 )
		PIN_SafeCopy(&(ReadBuffer.content), static_cast<UINT8*>(addr), 1);
	else if ( len == 2 )
		PIN_SafeCopy(&(ReadBuffer.content), static_cast<UINT16*>(addr), 2);
	else
		PIN_SafeCopy(&(ReadBuffer.content), static_cast<UINT32*>(addr), 4);


	KsMemReadTrace.save_data( &ReadBuffer, sizeof(MemOP) );

}

// Record a memory write record
static VOID rec_mem_write( ADDRINT pc, VOID * addr, UINT32 len )
{
	if ( InstCounter[pc] > InstRecordThreshold || !swtch.is_on() )
		return;

	if ( len > 4 ) // ignore this one!
		return;

	// notice that here we write back the data of last memory modification!
	// because PIN does not support to insert memory writing monitoring instruction after a memory modification operation
	// we just record last time modification's address and when a new memory modification happens, we record the last time operation's value.
	if ( WriteBuffer.addr != 0 )
	{
		if ( WriteBuffer.len == 1 )
			PIN_SafeCopy(&(WriteBuffer.content), static_cast<UINT8*>(WriteBuffer.addr), 1);
		else if ( WriteBuffer.len == 2 )
			PIN_SafeCopy(&(WriteBuffer.content), static_cast<UINT16*>(WriteBuffer.addr), 2);
		else if ( WriteBuffer.len == 4 )
			PIN_SafeCopy(&(WriteBuffer.content), static_cast<UINT32*>(WriteBuffer.addr), 4);
		
		/*
		if ( 1 != fwrite( &WriteBuffer, sizeof(MemOP), 1, KsMemWriteTrace ) )
		{
			puts("write mem error\n");
			exit(0);
		}
		*/
		KsMemWriteTrace.save_data( &WriteBuffer, sizeof(MemOP) );
	}

	// Finally, we record the current memory modification operation
	THREADID tid = ( PIN_ThreadId() & 0xFFFF );
	WriteBuffer.addr = addr;
	WriteBuffer.tid = tid;
	WriteBuffer.len = len;
	WriteBuffer.type = 'W';
	WriteBuffer.uid = ThreadUid[WriteBuffer.tid];
}

static VOID inst_recorder( const CONTEXT * const ctxt )
{
	ADDRINT pc = PIN_GetContextReg( ctxt, REG_INST_PTR );
	
	++InstCounter[pc];

	if ( InstCounter[pc] > InstRecordThreshold || !swtch.is_on() )
		return;

	static RegS IpBuffer;

	IpBuffer.eax = PIN_GetContextReg( ctxt, REG_EAX );
	IpBuffer.ebx = PIN_GetContextReg( ctxt, REG_EBX );
	IpBuffer.ecx = PIN_GetContextReg( ctxt, REG_ECX );
	IpBuffer.edx = PIN_GetContextReg( ctxt, REG_EDX );
	IpBuffer.edi = PIN_GetContextReg( ctxt, REG_EDI );
	IpBuffer.esi = PIN_GetContextReg( ctxt, REG_ESI );
	IpBuffer.ebp = PIN_GetContextReg( ctxt, REG_EBP );
	IpBuffer.esp = PIN_GetContextReg( ctxt, REG_ESP );
	IpBuffer.ip = pc;
	IpBuffer.id = PIN_ThreadId();
	ThreadIDs[IpBuffer.id] = 1;

	++ThreadUid[IpBuffer.id];
	IpBuffer.uid = ThreadUid[IpBuffer.id];
	
	KsTrace.save_data( &IpBuffer, sizeof(RegS) );
}


static VOID insert_mem_trace(INS ins)
{
    if (INS_IsMemoryWrite(ins))
		INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(rec_mem_write), IARG_INST_PTR, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);
	
    if ( INS_HasMemoryRead2(ins) )
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(rec_mem_read), IARG_INST_PTR, IARG_MEMORYREAD2_EA, IARG_MEMORYREAD_SIZE, IARG_END);

	if ( INS_IsMemoryRead(ins) )
		INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(rec_mem_read), IARG_INST_PTR, IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_END);

}

static void final_record()
{
	for ( size_t i = 0; i < sizeof(ThreadIDs); ++i )
		if (ThreadIDs[i] != 0)
			fprintf( kThread.fp(), "%d ", i );

	for ( map<ADDRINT, size_t>::const_iterator it = InstCounter.begin(); it != InstCounter.end(); ++it )
	{
		if ( it->second != 0 )
			fprintf( iCounter.fp(), "%08x: %d\n", it->first, it->second );
	}

	if ( WriteBuffer.addr != 0 )
	{
		if ( WriteBuffer.len == 1 )
			PIN_SafeCopy(&(WriteBuffer.content), static_cast<UINT8*>(WriteBuffer.addr), 1);
		else if ( WriteBuffer.len == 2 )
			PIN_SafeCopy(&(WriteBuffer.content), static_cast<UINT16*>(WriteBuffer.addr), 2);
		else if ( WriteBuffer.len == 4 )
			PIN_SafeCopy(&(WriteBuffer.content), static_cast<UINT32*>(WriteBuffer.addr), 4);
		
		KsMemWriteTrace.save_data( &WriteBuffer, sizeof(MemOP) );
	}


}

VOID ByeWorld(VOID *v)
{
	final_record();
}

// Pin calls this function every time a new instruction is encountered
static VOID instrumentor(INS ins, VOID *v)
{
	ADDRINT pc = INS_Address (ins);

	if ( pc == Config.getSwitchOnAddr() )
		swtch.set_sw(true);
	if ( pc == Config.getSwitchOffAddr() )
		swtch.set_sw(false);
	if ( pc == Config.getDetachPoint() )
		PIN_Detach();

	if ( Config.getAddrFilter().find(pc) != Config.getAddrFilter().end() )
	{
		// Insert a call to inst_recorder before every instruction, and pass it the IP
		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)inst_recorder, IARG_CONST_CONTEXT, IARG_END );

		insert_mem_trace(ins);

		if (INS_IsIndirectBranchOrCall(ins))
		{		
			if (Addr2str.find(pc) == Addr2str.end())
			{
				Addr2str[pc] = INS_Disassemble(ins);
			}

			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(log_ICF), IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_END);
		}
	}
}


static VOID Fini(INT32 code, VOID *v)
{
	final_record();
}


static bool init()
{
	memset( ThreadUid, 0, sizeof(ThreadUid) );

	if ( KsTrace.set_trace_file("data/ksTrace.lzo") == false )
		return false;
	if ( KsMemReadTrace.set_trace_file("data/ksMemReadTrace.lzo") == false )
		return false;
	if ( KsMemWriteTrace.set_trace_file("data/ksMemWriteTrace.lzo") == false )
		return false;

	return true;
}

int main(int argc, char *argv[])
{
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid 
    if( PIN_Init(argc,argv) )
    {
        return 1;
    }
    
	if ( !init() )
		return -1;


    TRACE_AddInstrumentFunction(bbl_trace, 0);
    INS_AddInstrumentFunction(instrumentor, 0);

	//PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddFiniFunction(Fini, 0);

	// Callback functions to invoke before
    // Pin releases control of the application
	PIN_AddDetachFunction(ByeWorld, 0);
   
    
    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
