static FileManager Logger("./data/FuncTracer.dll.log", "w");
static FileManager FpProf("./data/funcProfiling.log", "w");
static FileManager IDAFile("./data/funcBranching.log", "w");

static Compressor FuncTracer;

const static size_t MAX_THREADS = 0x100;

static vector< map<ADDRINT, unsigned long long> > FuncProfDic(MAX_THREADS);
static map<ADDRINT, set<ADDRINT> > CallMap;
static map<ADDRINT, set<ADDRINT> > Func2FuncMap;
static vector<ADDRINT> CallStack;
static ADDRINT CurrentFunc;

struct fun
{
	ADDRINT addr;
	size_t thread;
};


static VOID func_trace(ADDRINT pc, ADDRINT target)
{
	static fun B;

	// record how many callee one instruction has
	CallMap[pc].insert(target);

	// record how many callee one instruction has
	Func2FuncMap[CurrentFunc].insert(target);

	// record the execution times of one function
	FuncProfDic[B.thread][target] += 1;
	

	// record the execution sequences of all functions
	// format: caller, caller
	B.thread = PIN_ThreadId() & 0xFF;

	// caller
	B.addr = pc;
	FuncTracer.save_data( &B, sizeof(fun) );

	// callee
	B.addr = target;
	FuncTracer.save_data( &B, sizeof(fun) );

	if ( Config.in_addr_range(target) )
	{
		CurrentFunc = target;
		CallStack.push_back(CurrentFunc);
	}
}

static VOID ret_trace(ADDRINT pc, ADDRINT target)
{
	CallStack.pop_back();
	CurrentFunc = CallStack.back();
}

static VOID instrumentor(INS ins, VOID *v)
{
	if ( Config.in_addr_range( INS_Address(ins) ) )
	{
		std::string inst = INS_Disassemble(ins);
		if ( inst.find("call") != std::string::npos )
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(func_trace), IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_END);
		if ( inst.find("ret") != std::string::npos )
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(ret_trace), IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_END);
	}
}

// This function is called when the application exits
static VOID Fini(INT32 code, VOID *v)
{
	for ( size_t i = 0; i < MAX_THREADS; ++i )
	{
		if ( FuncProfDic[i].size() != 0 )
		{
			for ( map<ADDRINT, unsigned long long>::const_iterator it = FuncProfDic[i].begin(); it != FuncProfDic[i].end(); ++it )
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

	for ( map<ADDRINT, set<ADDRINT> >::const_iterator i = Func2FuncMap.begin(); i != Func2FuncMap.end(); ++i )
	{
		fprintf( IDAFile.fp(), "%08X-->", i->first );
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

	CurrentFunc = 0xcafebeef;
	CallStack.push_back(CurrentFunc);

    // Register Instruction to be called to instrument instructions
	TRACE_AddInstrumentFunction(bbl_trace, 0);

	INS_AddInstrumentFunction(instrumentor, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);
    
    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
