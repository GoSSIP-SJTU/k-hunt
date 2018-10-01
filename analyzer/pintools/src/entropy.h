#include <iostream>
#include <fstream>
#include <math.h>
#include <map>
#include "pin.H"
#include "kscope.h"

extern ConfigReader Config;
static FileManager MemTrace("data/entropy.log", "w");

static ADDRINT WIP = 0;
static VOID * WAddr = 0;

struct Slot
{
	u4 d[0x100];
};

static Slot * ReadSlot[0x10000];
static Slot * WriteSlot[0x10000];


/*
static vector<Slot> ReadEntropySlot;
static vector<Slot> WriteEntropySlot;
static map<ADDRINT, Slot> ReadEntropySlot;
static map<ADDRINT, Slot> WriteEntropySlot;
*/

#define SLOT(slot, ip)		(slot)[((ip) >> 16) & 0xFFFF]
#define SLOTD(slot, ip)		(slot)[((ip) >> 16) & 0xFFFF][(ip) & 0xFFFF]


double shannon( const Slot & slot )
{
    u4 counter = 0;
    forloop (i, 0, 0x100)
        counter += slot.d[i];
    
    double base = 0.0;
	double log2 = log(2.0);
    
	forloop (i, 0, 0x100)
	{
        if ( 0 != slot.d[i] )
		{
            double hertz = 1.0 * slot.d[i] / counter;
            base += log(hertz) / log2 * hertz ;
		}
	}

	if ( (base / -8) < 0.001 && (base / -8) > -0.001 )
		return 0.0;
    return base / -8;
}

// Record a memory read record
VOID mem_read( ADDRINT ip, VOID * addr, u4 len )
{
	if ( len > REG_SIZE ) return;

	forloop (i, 0, len)
		++SLOTD(ReadSlot, ip).d[static_cast<u1*>(addr)[i]];
}

// Record a memory write record
VOID mem_write( ADDRINT ip, VOID * addr, u4 len )
{
	WIP = ip;
	WAddr = addr;
}

VOID mem_write_content( u4 len )
{
	if ( len > REG_SIZE ) return;

	forloop (i, 0, len)
		++SLOTD(WriteSlot, WIP).d[static_cast<u1*>(WAddr)[i]];
}

// Pin calls this function every time a new instruction is encountered
VOID Inst_Entropy(INS ins, VOID *v)
{
	ADDRINT ip = INS_Address(ins);
	if ( Config.in_addr_set(ip) )
	{
		if ( SLOT(ReadSlot, ip) == NULL )
		{
			SLOT(ReadSlot, ip) = new Slot[0x10000];
		}
		memset( SLOTD(ReadSlot, ip).d, 0, 0x400 );
		
		if ( SLOT(WriteSlot, ip) == NULL )
		{
			SLOT(WriteSlot, ip) = new Slot[0x10000];
		}
		memset( SLOTD(WriteSlot, ip).d, 0, 0x400 );

		if (INS_IsMemoryWrite(ins))
		{
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(mem_write),
				IARG_INST_PTR, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);

			if (INS_HasFallThrough(ins))
				INS_InsertPredicatedCall(ins, IPOINT_AFTER, AFUNPTR(mem_write_content),
					IARG_MEMORYWRITE_SIZE, IARG_END);
			if (INS_IsBranchOrCall(ins))
				INS_InsertPredicatedCall(ins, IPOINT_TAKEN_BRANCH, AFUNPTR(mem_write_content),
					IARG_MEMORYWRITE_SIZE, IARG_END);
		}

		if ( INS_IsMemoryRead(ins) )
		{
			INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(mem_read), 
				IARG_INST_PTR, IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_END);
		}
		if ( INS_HasMemoryRead2(ins) )
		{
			INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(mem_read), 
				IARG_INST_PTR, IARG_MEMORYREAD2_EA, IARG_MEMORYREAD_SIZE, IARG_END);
		}
	}
}


// This function is called when the application exits
static VOID Fini_Entropy(INT32 code, VOID *v)
{
	for ( size_t ip = Config.get_codeStartAddr(); ip <= Config.get_codeEndAddr(); ++ip )
	{
		if ( Config.in_addr_set(ip) && SLOT(ReadSlot, ip) != NULL )
			fprintf( MemTrace.fp(), "R|%08x: %f\n", ip, shannon( SLOTD(ReadSlot, ip) ) );
	}
	for ( size_t ip = Config.get_codeStartAddr(); ip <= Config.get_codeEndAddr(); ++ip )
	{
		if ( Config.in_addr_set(ip) && SLOT(WriteSlot, ip) != NULL )
			fprintf( MemTrace.fp(), "W|%08x: %f\n", ip, shannon( SLOTD(WriteSlot, ip) ) );
	}

	fprintf( MemTrace.fp(), "--FINI--\n" );
	fflush(  MemTrace.fp() );
}


int main(int argc, char * argv[])
{
    // Initialize pin
    if ( PIN_Init(argc, argv) )
		return -1;

	forloop (i, 0, 0x10000)
	{
		ReadSlot[i] = WriteSlot[i] = NULL;
	}

	/*
	ReadEntropySlot = vector<Slot>( Config.get_codeEndAddr() - Config.get_codeStartAddr() );
	WriteEntropySlot = vector<Slot>( Config.get_codeEndAddr() - Config.get_codeStartAddr() );
	*/

	fprintf( MemTrace.fp(), "code section size: %d\n", Config.get_codeEndAddr() - Config.get_codeStartAddr() );

	TRACE_AddInstrumentFunction(bbl_trace, 0);
	INS_AddInstrumentFunction(Inst_Entropy, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini_Entropy, 0);
    
    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
