#include <set>

using std::set;

static FileManager Logger("./log/keyhunter.dll.log", "w");
static FileManager HuntLogger("./data/keyhunt.log", "w");

struct Page
{
	u1 b[0x10000];
};

const static u1 INTERNAL_INPUT = 0x01;
const static u1 EXTERNAL_INPUT = 0x10;

// shadow memory, each page contains 0x10000 bytes
static Page * Memory[0x10000];

static u1 Taint;
static set<ADDRINT> BBLMemCounter;

static bool AddrSwc = false;

static VOID PIN_FAST_ANALYSIS_CALL switch_on()
{
	AddrSwc = true;
}

static VOID PIN_FAST_ANALYSIS_CALL switch_off()
{
	AddrSwc = false;
}

static inline bool check()
{
	return AddrSwc;
}

#define PAGE(x) ((ADDRINT)(x) >> 16)
#define ADDR(x) ((ADDRINT)(x) & 0xFFFF)
#define MEM(x) Memory[PAGE((x))]->b[ADDR((x))]

static inline void taint_propagate( VOID * addr )
{
	// taint propagation
	u1 x = MEM(addr);
	if ( x )
	{
		BBLMemCounter.insert((ADDRINT)addr);
		Taint |= x;
	}
}
static VOID recorder_rr( ADDRINT ip, VOID * addr0, u4 len0, VOID * addr1, u4 len1 )
{
	if ( !check() ) return;

	if ( len0 > REG_SIZE || len1 > REG_SIZE ) // ignore this one!
		return;

	if ( NULL == Memory[PAGE(addr0)] )
		Memory[PAGE(addr0)] = new Page;

	taint_propagate(addr0);

	if ( NULL == Memory[PAGE(addr1)] )
		Memory[PAGE(addr1)] = new Page;

	taint_propagate(addr1);
}


static VOID recorder_rn( ADDRINT ip, VOID * addr0, u4 len0 )
{
	if ( !check() ) return;

	if ( len0 > REG_SIZE ) // ignore this one!
		return;

	if ( NULL == Memory[PAGE(addr0)] )
		Memory[PAGE(addr0)] = new Page;

	taint_propagate(addr0);
}

static VOID recorder_nr( ADDRINT ip, VOID * addr1, u4 len1 )
{
	if ( !check() ) return;

	if ( len1 > REG_SIZE ) // ignore this one!
		return;

	if ( NULL == Memory[PAGE(addr1)] )
		Memory[PAGE(addr1)] = new Page;

	taint_propagate(addr1);
}

static VOID recorder_w( ADDRINT ip, VOID * addr2, u4 len2 )
{
	if ( !check() ) return;

	if ( len2 > REG_SIZE ) // ignore this one!
		return;

	if ( NULL == Memory[PAGE(addr2)] )
		Memory[PAGE(addr2)] = new Page;

	// taint propagation
	MEM(addr2) = Taint;

	if ( Taint )
		fprintf( HuntLogger.fp(), "taint addr: %08x\n", addr2 );
}

static VOID reset_taint()
{
	Taint = 0;
	BBLMemCounter.clear();
}

static VOID bye_bye()
{
	PIN_Detach();
}

static VOID taint( const CONTEXT * const ctxt )
{
	ADDRINT pc = PIN_GetContextReg( ctxt, REG_INST_PTR );
	u4 eax = PIN_GetContextReg( ctxt, REG_EAX );
	u4 ebx = PIN_GetContextReg( ctxt, REG_EBX );
	u4 ecx = PIN_GetContextReg( ctxt, REG_ECX );
	u4 edx = PIN_GetContextReg( ctxt, REG_EDX );
	u4 edi = PIN_GetContextReg( ctxt, REG_EDI );
	u4 esi = PIN_GetContextReg( ctxt, REG_ESI );
	u4 ebp = PIN_GetContextReg( ctxt, REG_EBP );
	u4 esp = PIN_GetContextReg( ctxt, REG_ESP );

	/* hard coded */
	ADDRINT addr;

	forloop (i, 0, 12)
	{
		addr = eax + i;
		if ( NULL == Memory[PAGE(addr)] )
			Memory[PAGE(addr)] = new Page;
		MEM(addr) = INTERNAL_INPUT;
		fprintf( HuntLogger.fp(), "taint addr: %08x\n", addr );
	}
}


static VOID tracer(TRACE trace, VOID *v)
{
	if ( Config.in_addr_range( BBL_Address( TRACE_BblHead(trace) ) ) )
		fprintf( FpCodePool.fp(), "----Trace: %08x----\n", BBL_Address( TRACE_BblHead(trace) ) );

	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
		ADDRINT pc = BBL_Address(bbl);
		if ( Config.in_addr_range(pc) )
		{
			for ( INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
			{
				fprintf( FpCodePool.fp(), "%08x|%s\n", INS_Address(ins), INS_Disassemble(ins).c_str() );
			}
			fprintf( FpCodePool.fp(), "----\n" );

			if ( Config.get_detachPoint() ==  pc )
				BBL_InsertCall( bbl, IPOINT_BEFORE, (AFUNPTR)bye_bye, IARG_END );

			if ( Config.is_addrSwc_on() )
			{
				if ( pc == Config.get_switchOnAddr() )
					BBL_InsertCall(bbl, IPOINT_ANYWHERE, AFUNPTR(switch_on), IARG_FAST_ANALYSIS_CALL, IARG_END);	
			
				if ( pc == Config.get_switchOffAddr() )
					BBL_InsertCall(bbl, IPOINT_ANYWHERE, AFUNPTR(switch_off), IARG_FAST_ANALYSIS_CALL, IARG_END);	
			}
			else
			{
				// simply let address switch to be true;
				AddrSwc = true;
			}

			BBL_InsertCall(bbl, IPOINT_ANYWHERE, AFUNPTR(reset_taint), IARG_FAST_ANALYSIS_CALL, IARG_END);
		}
	}
}

static VOID instrumentor(INS ins, VOID * v)
{
	ADDRINT pc = INS_Address(ins);

	if ( !Config.in_addr_range(pc) )
		return;

	if ( INS_IsMemoryRead(ins) && INS_HasMemoryRead2(ins)  )
	{
		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)recorder_rr, 
			IARG_INST_PTR,
			IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, 
			IARG_MEMORYREAD2_EA, IARG_MEMORYREAD_SIZE, 
			IARG_END 
		);
	}
	else if ( INS_IsMemoryRead(ins) && !INS_HasMemoryRead2(ins)  )
	{
		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)recorder_rn, 
			IARG_INST_PTR,
			IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, 
			IARG_END 
		);
	}
	else if ( !INS_IsMemoryRead(ins) && INS_HasMemoryRead2(ins)  )
	{
		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)recorder_nr, 
			IARG_INST_PTR,
			IARG_MEMORYREAD2_EA, IARG_MEMORYREAD_SIZE, 
			IARG_END 
		);
	}
	
	if ( INS_IsMemoryWrite(ins)  )
	{
		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)recorder_w, 
			IARG_INST_PTR,
			IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, 
			IARG_END 
		);
	}

	if ( pc == 0x4053aa )
		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)taint, IARG_CONST_CONTEXT, IARG_END );
}

// This function is called when the application exits
static VOID Fini(INT32 code, VOID *v)
{
	size_t counter = 0;
	forloop( i, 0, 0x10000 )
	{
		if ( Memory[i] != NULL )
			++counter;
	}

	fprintf( Logger.fp(), "%d memory pages used\n", counter);

	fprintf( Logger.fp(), "----FINI KeyHunter----\n");
	fflush(Logger.fp());
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */


int main(int argc, char * argv[])
{
    // Initialize pin
    if ( PIN_Init(argc, argv) )
		return -1;

	fprintf( Logger.fp(), "----Injection----\n");

	forloop (i, 0, 0x10000)
		Memory[i] = NULL;

	TRACE_AddInstrumentFunction(tracer, 0);
	INS_AddInstrumentFunction(instrumentor, 0);
    PIN_AddFiniFunction(Fini, 0);
    

	// Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
