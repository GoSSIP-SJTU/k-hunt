static FileManager Logger("./data/branch.dll.log", "w");
static Compressor BBLTracer;

static map<ADDRINT, set<ADDRINT> > CallMap;

static InstCounter BranchCache;

struct Branch
{
	ADDRINT source;
	ADDRINT target;
};

static Branch B;

static bool AddrSwc = false;

static VOID PIN_FAST_ANALYSIS_CALL switch_on()
{
	AddrSwc = true;
}

static VOID PIN_FAST_ANALYSIS_CALL switch_off()
{
	AddrSwc = false;
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
				fprintf( FpCodePool.fp(), "%08x|%s\n", INS_Address (ins), INS_Disassemble(ins).c_str() );
			}
			fprintf( FpCodePool.fp(), "----\n" );
			fflush( FpCodePool.fp() );

			// insert switch function
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
		}
	}
}

static VOID call_trace(ADDRINT pc, ADDRINT target, BOOL taken)
{
	if ( !AddrSwc )
		return;

	if ( Config.in_addr_range(target) )
	{
		B.source = pc;
		if ( taken )
			B.target = target;
		else
			B.target = pc + 1;
	}

	BBLTracer.save_data( &B, sizeof(Branch) );
}


static VOID instrumentor(INS ins, VOID *v)
{
	if ( Config.in_addr_range( INS_Address(ins) ) )
	{
		if (INS_IsBranchOrCall(ins))
		{
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(call_trace), IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN, IARG_END);
		}
	}
}

static VOID Fini(INT32 code, VOID *v)
{
	fprintf( Logger.fp(), "----FINI BranchTracer----\n");
}

int main(int argc, char * argv[])
{
    if ( PIN_Init(argc, argv) )
		return -1;

	if ( !BBLTracer.set_trace_file("data/branchTracing.lzo") )
	{
		fprintf( Logger.fp(), "fail to set branch tracing lzo!!!\n");
		return -2;
	}

	BranchCache.init( Config.get_codeStartAddr(), Config.get_codeEndAddr() - Config.get_codeStartAddr() );

	TRACE_AddInstrumentFunction(tracer, 0);

	INS_AddInstrumentFunction(instrumentor, 0);

    PIN_AddFiniFunction(Fini, 0);

	fprintf( Logger.fp(), "----Injection----\n");
    PIN_StartProgram();
    
    return 0;
}
