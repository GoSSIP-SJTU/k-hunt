#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <set>
#include "pin.h"
#include "kscope.h"

using std::map;
using std::vector;

extern ConfigReader Config;

map<ADDRINT, ADDRINT> MemBook;


/* ================================================================== */
// Global variables 
/* ================================================================== */
static PIN_LOCK Sherlock;

static FileManager Logger("data/prov.dll.log", "w");
static FileManager InstMemLogger("data/instMemProv.log", "w");

static bool AddrSwc = false;


/* ================================================================== */
// instrumentation routines 
/* ================================================================== */
static void record(ADDRINT ip, ADDRINT addr, UINT32 len ) 
{
	for ( size_t i = 0; i < len; ++i )
	{
		if ( MemBook.find(addr + i) != MemBook.end() )
			fprintf( InstMemLogger.fp(), "%08x reads [%08x](%08x)\n", ip, addr + i, MemBook[addr + i] );
		else
			fprintf( InstMemLogger.fp(), "%08x reads [%08x](00000000)\n", ip, addr + i );
	}
}

static VOID update_mem( ADDRINT ip, VOID * addr, UINT32 len )
{
	if ( len > REG_SIZE ) // ignore this one!
		return;

	for ( size_t i = 0; i < len; ++i )
		MemBook[(ADDRINT)addr + i] = ip;
}

static VOID recorder_rr( ADDRINT ip, VOID * addr0, UINT32 len0, VOID * addr1, UINT32 len1 )
{
	if ( len0 > REG_SIZE || len1 > REG_SIZE ) // ignore this one!
		return;
	
	record( ip, (ADDRINT)addr0, len0 );
	record( ip, (ADDRINT)addr1, len1 );

}


static VOID recorder_r( ADDRINT ip, VOID * addr0, UINT32 len0 )
{
	if ( len0 > REG_SIZE ) // ignore this one!
		return;

	record( ip, (ADDRINT)addr0, len0 );
}

static VOID bye_bye()
{
	fclose( InstMemLogger.fp() );
	PIN_Detach();
}

// Pin calls this function every time a new instruction is encountered
static VOID instrumentor(INS ins, VOID *v)
{
	ADDRINT pc = INS_Address(ins);

	if ( Config.get_detachPoint() ==  pc )
	{
		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)bye_bye, IARG_END );
	}

	if ( Config.in_addr_range(pc) )
	{
		if ( INS_IsMemoryWrite(ins)  )
		{
			INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)update_mem, 
				IARG_INST_PTR,
				IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, 
				IARG_END 
			);
		}
	}

	if ( Config.in_addr_set(pc) )
	{
		if ( INS_IsMemoryRead(ins) && INS_HasMemoryRead2(ins) )
		{
			INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)recorder_rr, 
				IARG_INST_PTR,
				IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, 
				IARG_MEMORYREAD2_EA, IARG_MEMORYREAD_SIZE, 
				IARG_END 
			);
		}

		if ( INS_IsMemoryRead(ins) && !INS_HasMemoryRead2(ins) )
		{
			INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)recorder_r, 
				IARG_INST_PTR,
				IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, 
				IARG_END 
			);
		}
	}
}


static VOID Fini(INT32 code, VOID *v)
{
	fprintf( Logger.fp(), "mem provenance\n" );
}


int main(int argc, char *argv[])
{
    if( PIN_Init(argc,argv) )
        return 1;

    TRACE_AddInstrumentFunction(bbl_trace, 0);

    INS_AddInstrumentFunction(instrumentor, 0);

    PIN_AddFiniFunction(Fini, 0);

	PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
