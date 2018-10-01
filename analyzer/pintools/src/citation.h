#include <iostream>
#include <fstream>
#include <math.h>

#include "pin.h"
#include "kscope.h"

extern ConfigReader Config;

static FileManager MemTrace("data/citation.log", "w");
static FileManager FpCodePool("data/bblInst.log", "w");
static FileManager Logger("data/cite.dll.log", "w");

static map<ADDRINT, ADDRINT> WhoWriteThisAddr;
static map<ADDRINT, set<ADDRINT> > citationMap;

static map<ADDRINT, ADDRINT> Cache;
static map<ADDRINT, size_t> IPRCounter;
static map<ADDRINT, size_t> IPWCounter;

// Record a memory read record
VOID mem_read( ADDRINT ip, VOID * addr, UINT32 len )
{
	if ( IPRCounter[ip] > 0x1000 || len > 4 )
		return;

	++IPRCounter[ip];

	for ( size_t i = 0; i < len; ++i )
	{
		ADDRINT maddr = reinterpret_cast<ADDRINT>(addr) + i;

		// recording the reading of the external data content in the memory 
		if ( WhoWriteThisAddr.find( maddr ) == WhoWriteThisAddr.end() )
		{
			citationMap[ip].insert( 0xFACEB00C );
		}
		else
		{
			citationMap[ip].insert( WhoWriteThisAddr[maddr] );
		}
	}
	
}

// Record a memory write record
VOID mem_write( ADDRINT ip, VOID * addr, UINT32 len )
{
	if ( IPWCounter[ip] > 0x1000 || len > 4 )
		return;
	
	++IPWCounter[ip];

	for ( size_t i = 0; i < len; ++i )
	{
		if ( WhoWriteThisAddr.find(reinterpret_cast<ADDRINT>(addr) + i) == WhoWriteThisAddr.end() || WhoWriteThisAddr[reinterpret_cast<ADDRINT>(addr) + i] != ip )
			WhoWriteThisAddr[reinterpret_cast<ADDRINT>(addr) + i] = ip; // who is responsible for writting the specific address
	}

}

static VOID bbl_trace(TRACE trace, VOID *v)
{
	// Visit every basic block in the trace
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
		if ( Config.in_addr_range(BBL_Address(bbl)) )
		{
			for ( INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
			{
				fprintf( FpCodePool.fp(), "%08x|%s\n", INS_Address (ins), INS_Disassemble(ins).c_str() );
			}
			fprintf( FpCodePool.fp(), "----\n" );
		}
	}
}

// Pin calls this function every time a new instruction is encountered
VOID mem_probe(INS ins, VOID *v)
{
	ADDRINT pc = INS_Address (ins);

	/*
	static bool flag = false;
	if ( pc == Config.getSwitchOnAddr() )
		flag = true;
	if ( pc == Config.getSwitchOffAddr() )
		flag = false;

	if ( flag == false )
		return;
	*/
	string inst = INS_Disassemble(ins);
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
	fprintf( MemTrace.fp(), "external mem read: \n" );

	for ( map< ADDRINT, set<ADDRINT> >::const_iterator it = citationMap.begin(); it != citationMap.end(); ++it )
	{
		fprintf( MemTrace.fp(), "Inst#%08x relies on the following instrutctions:\n", it->first );
		for ( set<ADDRINT>::const_iterator i = it->second.begin(); i != it->second.end(); ++i )
		{
			fprintf( MemTrace.fp(), "%08x ", *i );
		}
		fprintf( MemTrace.fp(), "\n--------\n" );
	}

	fprintf( Logger.fp(), "citation analysis FINI\n" );
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
