#include <iostream>
#include <fstream>
#include <vector>
#include <map>

#include "pin.h"
#include "kscope.h"

using std::map;
using std::vector;

extern ConfigReader Config;

/* ================================================================== */
// Global variables 
/* ================================================================== */
static Bundler MemRBundler;
static Bundler MemWBundler;

static PIN_LOCK Sherlock;
static FileManager Logger("data/bundle.dll.log", "w");
static FileManager BundleTracer("data/bundle.log", "w");

static bool AddrSwc = false;


static VOID switch_on()
{
	AddrSwc = true;
}

static VOID switch_off()
{
	AddrSwc = false;
}

// Record a memory read record
static VOID mem_read( ADDRINT pc, VOID * addr, UINT32 len )
{
	if ( !AddrSwc || len > 4 ) // ignore this one!
		return;
	MemRBundler.add_record( pc, (ADDRINT)addr );
}

// Record a memory write record
static VOID mem_write( ADDRINT pc, VOID * addr, UINT32 len )
{
	if ( !AddrSwc || len > 4 )
		return;
	MemWBundler.add_record( pc, (ADDRINT)addr );
}

// Pin calls this function every time a new instruction is encountered
static VOID instrumentor(INS ins, VOID *v)
{
	ADDRINT pc = INS_Address (ins);

	if ( Config.in_addr_range(pc) )
	{
		if ( Config.is_addrSwc_on() )
		{
			if ( pc == Config.get_switchOnAddr() )
				INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)switch_on, IARG_END );
			if ( pc == Config.get_switchOffAddr() )
				INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)switch_off, IARG_END );
		}
		else
		{
			// simply let address switch to be true;
			AddrSwc = true;
		}
	}

	if ( Config.in_addr_range(pc) )
	{
	    if (INS_IsMemoryWrite(ins))
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(mem_write), IARG_INST_PTR, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);
	
		if ( INS_HasMemoryRead2(ins) )
			INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(mem_read), IARG_INST_PTR, IARG_MEMORYREAD2_EA, IARG_MEMORYREAD_SIZE, IARG_END);

		if ( INS_IsMemoryRead(ins) )
			INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(mem_read), IARG_INST_PTR, IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_END);
	}
}


static VOID Fini(INT32 code, VOID *v)
{
	fprintf( BundleTracer.fp(), "----memory read----\n" );
	MemRBundler.output_log( BundleTracer.fp() );
	
	fprintf( BundleTracer.fp(), "----memory write----\n" );
	MemWBundler.output_log( BundleTracer.fp() );
}


int main(int argc, char *argv[])
{
    if( PIN_Init(argc,argv) )
        return 1;
 
	MemRBundler.init( Config.get_codeStartAddr(), Config.get_codeEndAddr() - Config.get_codeStartAddr() );
	MemWBundler.init( Config.get_codeStartAddr(), Config.get_codeEndAddr() - Config.get_codeStartAddr() );

    TRACE_AddInstrumentFunction(bbl_trace, 0);
    INS_AddInstrumentFunction(instrumentor, 0);

	//PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
