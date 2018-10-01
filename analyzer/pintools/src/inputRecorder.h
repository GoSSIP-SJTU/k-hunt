#include <iostream>
#include <fstream>
#include <math.h>
#include "pin.H"
#include "kscope.h"

extern ConfigReader Config;

static FileManager MemTrace("data/ExtInput.bin", "wb");
static FileManager Logger("data/input.dll.log", "w");

/*
 * The lock for I/O.
 */
static PIN_LOCK fileLock;

static set<ADDRINT> Memory;
static map<ADDRINT, map<ADDRINT, size_t> > ExtInput;


// Record a memory read record
VOID mem_read( ADDRINT ip, VOID * addr, UINT32 len )
{
	static PIN_LOCK sherlock;

	struct
	{
		ADDRINT p;
		ADDRINT m;
		size_t c;
	} buffer;

	buffer.p = ip;

	PIN_GetLock(&sherlock, 1);
	for ( size_t i = 0; i < len; ++i )
	{
		ADDRINT maddr = reinterpret_cast<ADDRINT>(addr) + i;

		if ( Memory.find( maddr ) == Memory.end() )
		{
			buffer.m = maddr;
			buffer.c = reinterpret_cast<UINT8*>(maddr)[i];
			fwrite( &buffer, sizeof(buffer), 1, MemTrace.fp() );
		}
	}
	PIN_ReleaseLock(&sherlock);
}

// Record a memory write record
VOID mem_write( ADDRINT ip, VOID * addr, UINT32 len )
{
	for ( size_t i = 0; i < len; ++i )
	{
		Memory.insert(reinterpret_cast<ADDRINT>(addr) + i);
	}
}


// Pin calls this function every time a new instruction is encountered
VOID mem_probe(INS ins, VOID *v)
{
	ADDRINT pc = INS_Address (ins);

	if ( Config.in_addr_range(pc) )
	{
		if (INS_IsMemoryWrite(ins))
		{
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(mem_write), IARG_INST_PTR, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);
		}

		if ( INS_IsMemoryRead(ins) )
		{
			INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(mem_read), IARG_INST_PTR, IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_END);
		}
		if ( INS_HasMemoryRead2(ins) )
		{
			INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(mem_read), IARG_INST_PTR, IARG_MEMORYREAD2_EA, IARG_MEMORYREAD_SIZE, IARG_END);
		}
	}
}


// This function is called when the application exits
static VOID Fini(INT32 code, VOID *v)
{
	fprintf( Logger.fp(), "Ext input analysis FINI\n" );
}

int main(int argc, char * argv[])
{
    // Initialize pin
    if ( PIN_Init(argc, argv) )
		return -1;

    // Register Instruction to be called to instrument instructions
    TRACE_AddInstrumentFunction(bbl_trace, 0);

	// Register Instruction to be called to instrument instructions
    INS_AddInstrumentFunction(mem_probe, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);
    
	fprintf( Logger.fp(), "mem analysis starts!\n" );

    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
