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

enum
{
	MEM_READ = 0x1001,
	MEM_WRITE = 0x0110
};

struct MemRecord
{
	ADDRINT		addr;
	uint8_t		content[REG_SIZE];
	uint32_t	len;
};

struct KsRecord
{
	uint32_t	insNum;
	uint32_t	tid;
	ADDRINT		ip;
	ADDRINT		eax;
	ADDRINT		ebx;
	ADDRINT		ecx;
	ADDRINT		edx;
	ADDRINT		edi;
	ADDRINT		esi;
	ADDRINT		ebp;
	ADDRINT		esp;
	MemRecord r0;
	MemRecord r1;
	MemRecord w0;
};





/* ================================================================== */
// Global variables 
/* ================================================================== */

static size_t InsCount = 0;        //number of dynamically executed instructions
static PIN_LOCK Sherlock;

static FileManager Logger("data/ktrace.dll.log", "w");
// static FileManager KsTracer("data/ktrace.bin", "wb");
static Compressor KsTracer;

static THREADID ThreadToMonitor = 0xFFFF;

static InstCounter InsCtr;
static bool AddrSwc = false;
/* ================================================================== */
// instrumentation routines 
/* ================================================================== */

static VOID set_thread_id()
{
	if ( ThreadToMonitor == 0xFFFF )
	{
		ThreadToMonitor = PIN_ThreadId();
		fprintf( Logger.fp(), "thread: %d\n", ThreadToMonitor );
	}
}

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
	if ( !AddrSwc || ThreadToMonitor == 0xFFFF )
		return false;

	if ( PIN_ThreadId() != ThreadToMonitor )
		return false;

	return true;
}

static void rec_inst(const CONTEXT * const ctxt, KsRecord & k)
{
	k.ip = PIN_GetContextReg( ctxt, REG_INST_PTR );

	if ( InsCtr.inst_record_num(k.ip) > Config.get_instRecNum() )
		return;

	k.eax = PIN_GetContextReg( ctxt, REG_EAX );
	k.ebx = PIN_GetContextReg( ctxt, REG_EBX );
	k.ecx = PIN_GetContextReg( ctxt, REG_ECX );
	k.edx = PIN_GetContextReg( ctxt, REG_EDX );
	k.edi = PIN_GetContextReg( ctxt, REG_EDI );
	k.esi = PIN_GetContextReg( ctxt, REG_ESI );
	k.ebp = PIN_GetContextReg( ctxt, REG_EBP );
	k.esp = PIN_GetContextReg( ctxt, REG_ESP );
	k.insNum = InsCount++;
	k.tid = ThreadToMonitor;

	InsCtr.add_record(k.ip);

	KsTracer.save_data( &k, sizeof(KsRecord) );
}


static VOID recorder( const CONTEXT * const ctxt )
{
	if ( !check() ) return;

	static KsRecord k;
	k.r0.len = k.r1.len = k.w0.len = 0;

	rec_inst( ctxt, k );
}

static VOID recorder_rrw( const CONTEXT * const ctxt, VOID * addr0, UINT32 len0, VOID * addr1, UINT32 len1, VOID * addr2, UINT32 len2 )
{
	if ( !check() ) return;

	if ( len0 > REG_SIZE || len1 > REG_SIZE || len2 > REG_SIZE ) // ignore this one!
		return;

	static KsRecord k;

	k.r0.addr = reinterpret_cast<ADDRINT>(addr0);
	k.r1.addr = reinterpret_cast<ADDRINT>(addr1);
	k.w0.addr = reinterpret_cast<ADDRINT>(addr2);
	k.r0.len = len0;
	k.r1.len = len1;
	k.w0.len = len2;
	
	PIN_SafeCopy(k.r0.content, static_cast<UINT8*>(addr0), len0);
	PIN_SafeCopy(k.r1.content, static_cast<UINT8*>(addr1), len1);
	PIN_SafeCopy(k.w0.content, static_cast<UINT8*>(addr2), len2);

	rec_inst( ctxt, k );
}


static VOID recorder_rw( const CONTEXT * const ctxt, VOID * addr0, UINT32 len0, VOID * addr2, UINT32 len2 )
{
	if ( !check() ) return;

	if ( len0 > REG_SIZE || len2 > REG_SIZE ) // ignore this one!
		return;

	static KsRecord k;
	k.r1.len = 0;

	k.r0.addr = reinterpret_cast<ADDRINT>(addr0);
	k.w0.addr = reinterpret_cast<ADDRINT>(addr2);
	k.r0.len = len0;
	k.w0.len = len2;
	
	PIN_SafeCopy(k.r0.content, static_cast<UINT8*>(addr0), len0);
	PIN_SafeCopy(k.w0.content, static_cast<UINT8*>(addr2), len2);

	rec_inst( ctxt, k );
}

static VOID recorder_rr( const CONTEXT * const ctxt, VOID * addr0, UINT32 len0, VOID * addr1, UINT32 len1 )
{
	if ( !check() ) return;

	if ( len0 > REG_SIZE || len1 > REG_SIZE ) // ignore this one!
		return;

	static KsRecord k;
	k.w0.len = 0;

	k.r0.addr = reinterpret_cast<ADDRINT>(addr0);
	k.r1.addr = reinterpret_cast<ADDRINT>(addr1);
	k.r0.len = len0;
	k.r1.len = len1;
	
	PIN_SafeCopy(k.r0.content, static_cast<UINT8*>(addr0), len0);
	PIN_SafeCopy(k.r1.content, static_cast<UINT8*>(addr1), len1);

	rec_inst( ctxt, k );
}

static VOID recorder_r( const CONTEXT * const ctxt, VOID * addr0, UINT32 len0 )
{
	if ( !check() ) return;

	if ( len0 > REG_SIZE ) // ignore this one!
		return;

	static KsRecord k;
	k.r1.len = k.w0.len = 0;

	k.r0.addr = reinterpret_cast<ADDRINT>(addr0);
	k.r0.len = len0;

	PIN_SafeCopy(k.r0.content, static_cast<UINT8*>(addr0), len0);

	rec_inst( ctxt, k );
}

static VOID recorder_w( const CONTEXT * const ctxt, VOID * addr2, UINT32 len2 )
{
	if ( !check() ) return;

	if ( len2 > REG_SIZE ) // ignore this one!
		return;

	static KsRecord k;
	k.r0.len = k.r1.len = 0;

	k.w0.addr = reinterpret_cast<ADDRINT>(addr2);
	k.w0.len = len2;
	
	PIN_SafeCopy(k.w0.content, static_cast<UINT8*>(addr2), len2);

	rec_inst( ctxt, k );
}

// Pin calls this function every time a new instruction is encountered
static VOID instrumentor(INS ins, VOID *v)
{
	ADDRINT pc = INS_Address (ins);

	/*
	if ( InstRoster.find(pc) != InstRoster.end() )
		return;
	InstRoster.insert(pc);
	*/

	if ( pc == Config.get_threadToMonitor() )
		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)set_thread_id, IARG_END );

	if ( Config.in_addr_set(pc) )
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
				IARG_CONST_CONTEXT,
				IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, 
				IARG_MEMORYREAD2_EA, IARG_MEMORYREAD_SIZE, 
				IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, 
				IARG_END 
			);
		}
		else if ( INS_IsMemoryRead(ins) && !INS_HasMemoryRead2(ins) && INS_IsMemoryWrite(ins)  )
		{
			INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)recorder_rw, 
				IARG_CONST_CONTEXT,
				IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, 
				IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, 
				IARG_END 
			);
		}
		else if ( INS_IsMemoryRead(ins) && INS_HasMemoryRead2(ins) && !INS_IsMemoryWrite(ins)  )
		{
			INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)recorder_rr, 
				IARG_CONST_CONTEXT,
				IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, 
				IARG_MEMORYREAD2_EA, IARG_MEMORYREAD_SIZE, 
				IARG_END 
			);
		}
		else if ( !INS_IsMemoryRead(ins) && !INS_HasMemoryRead2(ins) && INS_IsMemoryWrite(ins)  )
		{
			INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)recorder_w, 
				IARG_CONST_CONTEXT,
				IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, 
				IARG_END 
			);
		}
		else if ( INS_IsMemoryRead(ins) && !INS_HasMemoryRead2(ins) && !INS_IsMemoryWrite(ins)  )
		{
			INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)recorder_r, 
				IARG_CONST_CONTEXT,
				IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, 
				IARG_END 
			);
		}
		else
		{
			INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)recorder, IARG_CONST_CONTEXT, IARG_END );
		}
	}
}



// Pin calls this function every time a new basic block is encountered
// It inserts a call to docount
static VOID bbl_print(TRACE trace, VOID *v)
{
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
		}
	}
}


static VOID Fini(INT32 code, VOID *v)
{
	fprintf( Logger.fp(), "kTracing.lzo -- InsCount :%d\n", InsCount );
}


int main(int argc, char *argv[])
{
    if( PIN_Init(argc,argv) )
        return 1;

	if ( !KsTracer.set_trace_file("data/ksTracing.lzo") )
	{
		fprintf( Logger.fp(), "fail to set ksTracing lzo!!!\n");
		return -2;
	}

	InsCtr.init( Config.get_codeStartAddr(), Config.get_codeEndAddr() - Config.get_codeStartAddr() );

    TRACE_AddInstrumentFunction(bbl_print, 0);

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
