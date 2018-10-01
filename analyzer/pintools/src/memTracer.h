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

struct MemRecord
{
	ADDRINT		addr;
	uint8_t		content[REG_SIZE];
	uint32_t	len;
};

struct MsRecord
{
	ADDRINT	ip;
	THREADID tid;
	MemRecord r0;
	MemRecord r1;
	MemRecord w0;
};


/* ================================================================== */
// Global variables 
/* ================================================================== */
static PIN_LOCK Sherlock;

static FileManager Logger("data/mtrace.dll.log", "w");
static Compressor MsTracer;

static bool AddrSwc = false;
/* ================================================================== */
// instrumentation routines 
/* ================================================================== */


static VOID switch_on()
{
	AddrSwc = true;
}

static VOID switch_off()
{
	AddrSwc = false;
}

static bool check()
{
	if ( !AddrSwc )
		return false;

	return true;
}

static void rec_inst(ADDRINT ip, MsRecord & k)
{
	k.ip = ip;
	k.tid = PIN_ThreadId();
	MsTracer.save_data( &k, sizeof(MsRecord) );
}

static VOID recorder_rrw( ADDRINT ip, VOID * addr0, UINT32 len0, VOID * addr1, UINT32 len1, VOID * addr2, UINT32 len2 )
{
	if ( !check() ) return;

	if ( len0 > REG_SIZE || len1 > REG_SIZE || len2 > REG_SIZE ) // ignore this one!
		return;

	static MsRecord k;

	k.r0.addr = reinterpret_cast<ADDRINT>(addr0);
	k.r1.addr = reinterpret_cast<ADDRINT>(addr1);
	k.w0.addr = reinterpret_cast<ADDRINT>(addr2);
	k.r0.len = len0;
	k.r1.len = len1;
	k.w0.len = len2;
	
	PIN_SafeCopy(k.r0.content, static_cast<UINT8*>(addr0), len0);
	PIN_SafeCopy(k.r1.content, static_cast<UINT8*>(addr1), len1);
	PIN_SafeCopy(k.w0.content, static_cast<UINT8*>(addr2), len2);

	rec_inst( ip, k );
}


static VOID recorder_rw( ADDRINT ip, VOID * addr0, UINT32 len0, VOID * addr2, UINT32 len2 )
{
	if ( !check() ) return;

	if ( len0 > REG_SIZE || len2 > REG_SIZE ) // ignore this one!
		return;

	static MsRecord k;
	k.r1.len = 0;

	k.r0.addr = reinterpret_cast<ADDRINT>(addr0);
	k.w0.addr = reinterpret_cast<ADDRINT>(addr2);
	k.r0.len = len0;
	k.w0.len = len2;
	
	PIN_SafeCopy(k.r0.content, static_cast<UINT8*>(addr0), len0);
	PIN_SafeCopy(k.w0.content, static_cast<UINT8*>(addr2), len2);

	rec_inst( ip, k );
}

static VOID recorder_rr( ADDRINT ip, VOID * addr0, UINT32 len0, VOID * addr1, UINT32 len1 )
{
	if ( !check() ) return;

	if ( len0 > REG_SIZE || len1 > REG_SIZE ) // ignore this one!
		return;

	static MsRecord k;
	k.w0.len = 0;

	k.r0.addr = reinterpret_cast<ADDRINT>(addr0);
	k.r1.addr = reinterpret_cast<ADDRINT>(addr1);
	k.r0.len = len0;
	k.r1.len = len1;
	
	PIN_SafeCopy(k.r0.content, static_cast<UINT8*>(addr0), len0);
	PIN_SafeCopy(k.r1.content, static_cast<UINT8*>(addr1), len1);

	rec_inst( ip, k );
}

static VOID recorder_r( ADDRINT ip, VOID * addr0, UINT32 len0 )
{
	if ( !check() ) return;

	if ( len0 > REG_SIZE ) // ignore this one!
		return;

	static MsRecord k;
	k.r1.len = k.w0.len = 0;

	k.r0.addr = reinterpret_cast<ADDRINT>(addr0);
	k.r0.len = len0;

	PIN_SafeCopy(k.r0.content, static_cast<UINT8*>(addr0), len0);

	rec_inst( ip, k );
}

static VOID recorder_w( ADDRINT ip, VOID * addr2, UINT32 len2 )
{
	if ( !check() ) return;

	if ( len2 > REG_SIZE ) // ignore this one!
		return;

	static MsRecord k;
	k.r0.len = k.r1.len = 0;

	k.w0.addr = reinterpret_cast<ADDRINT>(addr2);
	k.w0.len = len2;
	
	PIN_SafeCopy(k.w0.content, static_cast<UINT8*>(addr2), len2);

	rec_inst( ip, k );
}

static VOID bye_bye()
{
	PIN_Detach();
}

// Pin calls this function every time a new instruction is encountered
static VOID instrumentor(INS ins, VOID *v)
{
	ADDRINT pc = INS_Address(ins);

	if ( Config.get_detachPoint() ==  pc )
		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)bye_bye, IARG_END );

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

		if ( INS_IsMemoryRead(ins) && INS_HasMemoryRead2(ins) && INS_IsMemoryWrite(ins)  )
		{
			INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)recorder_rrw, 
				IARG_INST_PTR,
				IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, 
				IARG_MEMORYREAD2_EA, IARG_MEMORYREAD_SIZE, 
				IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, 
				IARG_END 
			);
		}
		else if ( INS_IsMemoryRead(ins) && !INS_HasMemoryRead2(ins) && INS_IsMemoryWrite(ins)  )
		{
			INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)recorder_rw, 
				IARG_INST_PTR,
				IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, 
				IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, 
				IARG_END 
			);
		}
		else if ( INS_IsMemoryRead(ins) && INS_HasMemoryRead2(ins) && !INS_IsMemoryWrite(ins)  )
		{
			INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)recorder_rr, 
				IARG_INST_PTR,
				IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, 
				IARG_MEMORYREAD2_EA, IARG_MEMORYREAD_SIZE, 
				IARG_END 
			);
		}
		else if ( !INS_IsMemoryRead(ins) && !INS_HasMemoryRead2(ins) && INS_IsMemoryWrite(ins)  )
		{
			INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)recorder_w, 
				IARG_INST_PTR,
				IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, 
				IARG_END 
			);
		}
		else if ( INS_IsMemoryRead(ins) && !INS_HasMemoryRead2(ins) && !INS_IsMemoryWrite(ins)  )
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
	fprintf( Logger.fp(), "memTracing.lzo\n" );
}


int main(int argc, char *argv[])
{
    if( PIN_Init(argc,argv) )
        return 1;

	if ( !MsTracer.set_trace_file("data/memTracing.lzo") )
	{
		fprintf( Logger.fp(), "fail to set memTracing lzo!!!\n");
		return -2;
	}

    TRACE_AddInstrumentFunction(bbl_trace, 0);

    INS_AddInstrumentFunction(instrumentor, 0);

    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
