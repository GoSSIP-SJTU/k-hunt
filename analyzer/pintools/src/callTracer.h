static FileManager Logger("./data/FuncTracer.dll.log", "w");
static FileManager FpProf("./data/bblProfiling.log", "w");
static FileManager IDAFile("./data/c.log", "w");

static Compressor FuncTracer;

const static size_t MAX_THREADS = 0x100;

static vector< map<ADDRINT, unsigned long long> > FuncProfDic(MAX_THREADS);
static map<ADDRINT, set<ADDRINT> > CallMap;

struct fun
{
	ADDRINT addr;
	size_t thread;
};

static fun B;


static VOID func_trace(ADDRINT pc, ADDRINT target)
{
	CallMap[pc].insert(target);

	B.addr = target;
	B.thread = PIN_ThreadId() & 0xFF;

	FuncProfDic[B.thread][target] += 1;

	FuncTracer.save_data( &B, sizeof(fun) );
}

static VOID instrumentor(INS ins, VOID *v)
{
	if ( Config.in_addr_range( INS_Address(ins) ) && INS_IsIndirectBranchOrCall(ins) )
	{
		std::string inst = INS_Disassemble(ins);
		if ( inst.find("call") != std::string::npos )
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(func_trace), IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_END);
	}
}

// This function is called when the application exits
static VOID Fini(INT32 code, VOID *v)
{
	for ( size_t i = 0; i < MAX_THREADS; ++i )
	{
		if ( FuncProfDic[i].size() != 0 )
		{
			for ( map<ADDRINT, unsigned long long>::const_iterator it = BBLProfDic[i].begin(); it != BBLProfDic[i].end(); ++it )
			{
				fprintf( FpProf.fp(), "%08X@%04d: %lld\n", it->first, i, it->second );
			}
		}
	}
	
	for ( map<ADDRINT, set<ADDRINT> >::const_iterator i = CallMap.begin(); i != CallMap.end(); ++i )
	{
		fprintf( IDAFile.fp(), "%08X branches to: ", i->first );
		for ( set<ADDRINT>::const_iterator j = i->second.begin(); j != i->second.end(); ++j )
		{
			fprintf( IDAFile.fp(), "%08X ", *j );
		}
		fprintf( IDAFile.fp(), "\n" );
	}

	fprintf( Logger.fp(), "----FINI FuncTracer----\n");
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

	if ( !FuncTracer.set_trace_file("data/callTracing.lzo") )
	{
		fprintf( Logger.fp(), "fail to set callTracing lzo!!!\n");
		return -2;
	}

	fprintf( Logger.fp(), "----Injection----\n");

    // Register Instruction to be called to instrument instructions
	TRACE_AddInstrumentFunction(bbl_trace, 0);

	INS_AddInstrumentFunction(instrumentor, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);
    
    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
