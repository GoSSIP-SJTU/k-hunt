static FileManager Logger("./data/bbl.dll.log", "w");
static FileManager FpProf("./data/bblProfiling.log", "w");
static FileManager IDAFile("./data/ida.log", "w");

static Compressor BBLTracer;

typedef unsigned long long u8;

static vector<u8> BBLProfDic;
static map<ADDRINT, set<ADDRINT> > CallMap;

struct bbl
{
	ADDRINT addr;
	size_t thread;
};

static bbl B;

static bool AddrSwc = false;

static VOID PIN_FAST_ANALYSIS_CALL switch_on()
{
	AddrSwc = true;
}

static VOID PIN_FAST_ANALYSIS_CALL switch_off()
{
	AddrSwc = false;
}

static VOID PIN_FAST_ANALYSIS_CALL bblTrace(ADDRINT startAddr)
{
	if ( !AddrSwc )
		return;

	ADDRINT addr = startAddr - Config.get_codeStartAddr();
	++BBLProfDic[addr];

	// BBLTracer.save_data( &B, sizeof(bbl) );
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

			BBL_InsertCall(bbl, IPOINT_ANYWHERE, AFUNPTR(bblTrace), IARG_FAST_ANALYSIS_CALL, IARG_ADDRINT, BBL_Address(bbl), IARG_END);
		}
	}
}

static VOID call_trace(ADDRINT pc, ADDRINT target)
{
	CallMap[pc].insert(target);
}

static VOID instrumentor(INS ins, VOID *v)
{
	if ( Config.in_addr_range( INS_Address(ins) ) )
	{
		if (INS_IsIndirectBranchOrCall(ins))
		{		
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(call_trace), IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_END);
		}
	}
}

// This function is called when the application exits
static VOID Fini(INT32 code, VOID *v)
{
	for ( size_t i = Config.get_codeStartAddr(); i < Config.get_codeEndAddr(); ++i )
	{
		u8 t = BBLProfDic[i - Config.get_codeStartAddr()];
		if ( t != 0 )
			fprintf( FpProf.fp(), "%08x: %llu\n", i, t );
	}
	
	fprintf( Logger.fp(), "----FINI BBLTracer----\n");
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

	if ( !BBLTracer.set_trace_file("data/bblTracing.lzo") )
	{
		fprintf( Logger.fp(), "fail to set bblTracing lzo!!!\n");
		return -2;
	}

	fprintf( Logger.fp(), "----Injection----\n");

	BBLProfDic = vector<u8>( Config.get_codeSectionSize(), 0 );
    // Register Instruction to be called to instrument instructions
	TRACE_AddInstrumentFunction(tracer, 0);

	// INS_AddInstrumentFunction(instrumentor, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);
    
    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
