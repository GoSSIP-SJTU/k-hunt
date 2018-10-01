#include <iostream>
#include <fstream>
#include <math.h>
#include "pin.H"
#include "kscope.h"

extern ConfigReader Config;

static FileManager FpCodePool("data/bblInst.log", "w");
static FileManager MemTrace("data/memTrace.log", "w");
static FileManager Logger("data/mem.dll.log", "w");

/*
 * The lock for I/O.
 */
static PIN_LOCK fileLock;

static ADDRINT WIP = 0;
static VOID * WAddr = 0;

struct Slot
{
	unsigned int d[256];
};

static map<ADDRINT, size_t> MemRmap;
static map<ADDRINT, size_t> MemWmap;

static map<ADDRINT, map<ADDRINT, size_t> > detailedRmap;
static map<ADDRINT, map<ADDRINT, size_t> > detailedWmap;

static map<ADDRINT, size_t> whoWriteThisMemory;
static map<ADDRINT, map<ADDRINT, size_t> > citationMap;


#ifdef SHANNON
static map<ADDRINT, Slot> ReadEntropySlot;
static map<ADDRINT, Slot> WriteEntropySlot;

double shannon( const Slot & slot )
{
    unsigned int counter = 0;
    for ( size_t i = 0; i < 256; ++i )
        counter += slot.d[i];
    
    double base = 0.0;
	double log2 = log(2.0);
    
	for ( size_t i = 0; i < 256; ++i )
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
#endif


// Record a memory read record
VOID mem_read( ADDRINT ip, VOID * addr, UINT32 len )
{
	if ( len > 4 )
		return;

	for ( size_t i = 0; i < len; ++i )
	{
		ADDRINT maddr = reinterpret_cast<ADDRINT>(addr) + i;

		// recording the reading of the external data content in the memory 
		if ( whoWriteThisMemory.find( maddr ) == whoWriteThisMemory.end() )
		{
			whoWriteThisMemory[maddr] = 0xFACEB00C;
			MemRmap[maddr] = reinterpret_cast<UINT8*>(maddr)[i];
		}

		// recording which memory writting instruction is cited
		citationMap[ whoWriteThisMemory[maddr] ][ip] += 1;

		// recording current instruciton's reading behavior
		detailedRmap[ip][maddr] += 1;

#ifdef SHANNON
		++ReadEntropySlot[ip].d[ static_cast<UINT8*>(maddr)[i] ];
#endif
	}
}

// Record a memory write record
VOID mem_write( ADDRINT ip, VOID * addr, UINT32 len )
{
	if ( len > 4 )
		return;

	WIP = ip;
	WAddr = addr;

	for ( size_t i = 0; i < len; ++i )
	{
		// who is responsible for writting the specific address
		whoWriteThisMemory[reinterpret_cast<ADDRINT>(addr) + i] = ip;

		// how many address contents does this instruciton wirte
		detailedWmap[ip][reinterpret_cast<ADDRINT>(addr) + i] += 1;

		MemWmap[reinterpret_cast<ADDRINT>(addr) + i] = 0;
	}
}

VOID mem_write_content( UINT32 len )
{
	
	for ( size_t i = 0; i < len; ++i )
	{
		// to record the data output. After the execution, the written data is the output.
		MemWmap[reinterpret_cast<ADDRINT>(WAddr) + i] = static_cast<UINT8*>(WAddr)[i];
	}

#ifdef SHANNON
	for ( size_t i = 0; i < len; ++i )
	{
		++WriteEntropySlot[WIP].d[ static_cast<UINT8*>(WAddr)[i] ];
	}
#endif
}

static VOID bbl_trace(TRACE trace, VOID *v)
{
	// Visit every basic block in the trace
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
		ADDRINT pc = BBL_Address(bbl);
		if ( pc >= Config.getCodeStartAddr() && pc <= Config.getCodeEndAddr() )
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

	static bool flag = false;
	if ( pc == Config.getSwitchOnAddr() )
		flag = true;
	if ( pc == Config.getSwitchOffAddr() )
		flag = false;

	if ( flag == false )
		return;

	if ( Config.in_addr_set(pc) )
	{
		if (INS_IsMemoryWrite(ins))
		{
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(mem_write), IARG_INST_PTR, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);

			if (INS_HasFallThrough(ins))
				INS_InsertPredicatedCall(ins, IPOINT_AFTER, AFUNPTR(mem_write_content), IARG_MEMORYWRITE_SIZE, IARG_END);
			if (INS_IsBranchOrCall(ins))
				INS_InsertPredicatedCall(ins, IPOINT_TAKEN_BRANCH, AFUNPTR(mem_write_content), IARG_MEMORYWRITE_SIZE, IARG_END);
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
	size_t Threshold = 0x10;

#ifdef SHANNON
	/* shannon entropy */
	for ( size_t i = Config.getCodeStartAddr(); i < Config.getCodeEndAddr(); ++i )
	{
		if ( Config.getAddrFilter().find(i) != Config.getAddrFilter().end() )
		{
			fprintf( MemTrace.fp(), "R|%08x: %f\n", i + Config.getCodeStartAddr(), shannon( ReadEntropySlot[i] ) );
			fprintf( MemTrace.fp(), "W|%08x: %f\n", i + Config.getCodeStartAddr(), shannon( WriteEntropySlot[i] ) );
		}
	}
#endif

	fprintf( MemTrace.fp(), "external mem read: \n" );
	for ( map<ADDRINT, size_t>::const_iterator it = MemRmap.begin(); it != MemRmap.end(); ++it )
	{
		fprintf( MemTrace.fp(), "[%08x]:%02x, ", it->first, it->second );
	}
	fprintf( MemTrace.fp(), "\n" );

	fprintf( MemTrace.fp(), "mem write: \n" );
	for ( map<ADDRINT, size_t>::const_iterator it = MemWmap.begin(); it != MemWmap.end(); ++it )
	{
		fprintf( MemTrace.fp(), "[%08x]:%02x, ", it->first, it->second );
	}
	fprintf( MemTrace.fp(), "\n" );

	fprintf( Logger.fp(), "rmap: %d, wmap: %d\n", detailedRmap.size(), detailedWmap.size() );

	ADDRINT lastOne;
	size_t counter;

	for ( map<ADDRINT, map<ADDRINT, size_t> >::const_iterator it = detailedRmap.begin(); it != detailedRmap.end(); ++it )
	{
		size_t total = 0;

		if ( it->second.size() > Threshold )
		{
			lastOne = 0;
			counter = 0;
			fprintf( MemTrace.fp(), "mem read: [" );
			for ( map<ADDRINT, size_t>::const_iterator jt = it->second.begin(); jt != it->second.end(); ++jt )
			{
				total += jt->second;

				// continous memory region?
				if ( lastOne + 1 == jt->first )
				{
					counter += 1;
				}
				else
				{
					if ( counter != 0 )
					{
						fprintf( MemTrace.fp(), " + %d; ", counter );
						counter = 0;
					}
					fprintf( MemTrace.fp(), "%08x, ", jt->first );
				}

				lastOne = jt->first;
			}
			if ( counter != 0 )
			{
				fprintf( MemTrace.fp(), " + %d; ", counter );
			}
			fprintf( MemTrace.fp(), "]\n" );

			fprintf( MemTrace.fp(), "R|%08x: total -- %d, uniq -- %d\n", it->first, total, it->second.size() );
		}

		
	}


	// recording memroy write operations
	for ( map<ADDRINT, map<ADDRINT, size_t> >::const_iterator it = detailedWmap.begin(); it != detailedWmap.end(); ++it )
	{
		size_t total = 0;

		if ( it->second.size() > Threshold )
		{
			lastOne = 0;
			counter = 0;
			fprintf( MemTrace.fp(), "mem written: [" );
			for ( map<ADDRINT, size_t>::const_iterator jt = it->second.begin(); jt != it->second.end(); ++jt )
			{
				total += jt->second;

				// continous memory region?
				if ( lastOne + 1 == jt->first )
				{
					counter += 1;
				}
				else
				{
					if ( counter != 0 )
					{
						fprintf( MemTrace.fp(), " + %d; ", counter );
						counter = 0;
					}
					fprintf( MemTrace.fp(), "%08x, ", jt->first );
				}
				lastOne = jt->first;
			}
			if ( counter != 0 )
			{
				fprintf( MemTrace.fp(), " + %d; ", counter );
			}
			fprintf( MemTrace.fp(), "]\n" );

			fprintf( MemTrace.fp(), "W|%08x: total -- %d, uniq -- %d\n", it->first, total, it->second.size() );
		}
	}

	for ( map<ADDRINT, map<ADDRINT, size_t> >::const_iterator it = citationMap.begin(); it != citationMap.end(); ++it )
	{
		for ( map<ADDRINT, size_t>::const_iterator jt = it->second.begin(); jt != it->second.end(); ++jt )
		{
			fprintf( MemTrace.fp(), "%08x|cited by [%08x]: %d\n", it->first, jt->first, jt->second );
		}
	}

	fprintf( Logger.fp(), "mem analysis FINI\n" );
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
