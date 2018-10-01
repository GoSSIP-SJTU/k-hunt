#include <stdio.h>
#include <algorithm>
#include "pin.h"
#include "kscope.h"

extern ConfigReader Config;

static FileManager Logger("config/fun.log", "w");
static FileManager FpFuncAnalysis("data/funcAnalyzing.log", "w");
static FileManager FpCodePool("data/inst.log", "w");
static FileManager FpFuncPool("data/func.log", "w");

struct MemUseInfo
{
	size_t callAddr;
	size_t funcAddr;
	size_t totalMemRead;
	size_t totalMemWrite;
	set<ADDRINT> memRead;
	set<ADDRINT> memWrite;
};

static const size_t MAX_STACK_DEPTH = 0x800;
static const size_t MAX_THREAD = 0x40;
static size_t CTR[MAX_THREAD] = {0};
static MemUseInfo FuncInfo[MAX_THREAD][MAX_STACK_DEPTH];

static VOID call_probe( ADDRINT callTarget, ADDRINT pc )
{
	if ( callTarget >= Config.getCodeStartAddr() && callTarget <= Config.getCodeEndAddr() )
	{
		fprintf( FpFuncPool.fp(), "THREAD[%02d]: %08x calls %08x\n", PIN_ThreadId(), pc, callTarget );

		/*
		++CTR[PIN_ThreadId()];
	
		if ( CTR[PIN_ThreadId()] >= MAX_STACK_DEPTH )
		{
			fprintf( Logger.fp(), "stack overflow\n");
			return;
		}

		FuncInfo[PIN_ThreadId()][CTR[PIN_ThreadId()]].totalMemWrite = 0;
		FuncInfo[PIN_ThreadId()][CTR[PIN_ThreadId()]].totalMemRead = 0;
		FuncInfo[PIN_ThreadId()][CTR[PIN_ThreadId()]].funcAddr = callTarget;
		FuncInfo[PIN_ThreadId()][CTR[PIN_ThreadId()]].callAddr = pc;
		*/
	}
}

static VOID return_probe( ADDRINT retTarget, ADDRINT pc )
{
	fprintf( FpFuncPool.fp(), "THREAD[%02d]: %08x returns to %08x\n", PIN_ThreadId(), pc, retTarget );

	/*
	if ( CTR[PIN_ThreadId()] >= MAX_STACK_DEPTH )
	{
		fprintf( Logger.fp(), "stack overflow\n");
		return;
	}

	fprintf( FpFuncAnalysis.fp(), "[%02d]|FUNC: %08x called by %08x; return at %08x\n", PIN_ThreadId(), FuncInfo[PIN_ThreadId()][CTR[PIN_ThreadId()]].funcAddr, FuncInfo[PIN_ThreadId()][CTR[PIN_ThreadId()]].callAddr, pc );
	fprintf( FpFuncAnalysis.fp(), "[%02d]|totalMemRead: %d\n", PIN_ThreadId(), FuncInfo[PIN_ThreadId()][CTR[PIN_ThreadId()]].totalMemRead );
	fprintf( FpFuncAnalysis.fp(), "[%02d]|totalMemWrite: %d\n", PIN_ThreadId(), FuncInfo[PIN_ThreadId()][CTR[PIN_ThreadId()]].totalMemWrite );
	fprintf( FpFuncAnalysis.fp(), "[%02d]|uniqMemRead: %d\n", PIN_ThreadId(), FuncInfo[PIN_ThreadId()][CTR[PIN_ThreadId()]].memRead.size() );
	fprintf( FpFuncAnalysis.fp(), "[%02d]|uniqMemWrite: %d\n--------\n", PIN_ThreadId(), FuncInfo[PIN_ThreadId()][CTR[PIN_ThreadId()]].memWrite.size() );
	
	--CTR[PIN_ThreadId()];
	*/
}


// Record a memory read record
static VOID rec_mem_read( ADDRINT addr, UINT32 len )
{
	if ( len > sizeof(int) ) // ignore this one!
		return;

	if ( CTR[PIN_ThreadId()] >= MAX_STACK_DEPTH )
	{
		fprintf( Logger.fp(), "stack overflow\n");
		return;
	}

	for ( size_t i = 0; i < len; ++i )
	{
		++FuncInfo[PIN_ThreadId()][CTR[PIN_ThreadId()]].totalMemRead;
		FuncInfo[PIN_ThreadId()][CTR[PIN_ThreadId()]].memRead.insert(addr + i);
	}
}

// Record a memory write record
static VOID rec_mem_write( ADDRINT addr, UINT32 len )
{
	if ( len > sizeof(int) ) // ignore this one!
		return;

	if ( CTR[PIN_ThreadId()] >= MAX_STACK_DEPTH )
	{
		fprintf( Logger.fp(), "stack overflow\n");
		return;
	}

	for ( size_t i = 0; i < len; ++i )
	{
		//++FuncInfo[PIN_ThreadId()][CTR[PIN_ThreadId()]].totalMemWrite;
		//FuncInfo[PIN_ThreadId()][CTR[PIN_ThreadId()]].memWrite.insert(addr + i);
	}
}


// Pin calls this function every time a new instruction is encountered
static VOID Instruction(INS ins, VOID *v)
{
	ADDRINT pc = INS_Address (ins);

	if ( pc >= Config.getCodeStartAddr() && pc <= Config.getCodeEndAddr() )
	{
		fprintf( FpCodePool.fp(), "%08x|%s\n", INS_Address (ins), INS_Disassemble(ins).c_str() );

		if ( INS_IsCall(ins) )
		{
			INS_InsertCall(	ins, IPOINT_TAKEN_BRANCH, AFUNPTR(call_probe), IARG_BRANCH_TARGET_ADDR, IARG_INST_PTR, IARG_END );
		}
		else if ( INS_IsRet(ins) )
		{
			INS_InsertCall(	ins, IPOINT_TAKEN_BRANCH, AFUNPTR(return_probe), IARG_BRANCH_TARGET_ADDR, IARG_INST_PTR, IARG_END );
		}
		else
		{
			/*
			if (INS_IsMemoryWrite(ins))
				INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(rec_mem_write), IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);
			if ( INS_HasMemoryRead2(ins) )
				INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(rec_mem_read), IARG_MEMORYREAD2_EA, IARG_MEMORYREAD_SIZE, IARG_END);
			if ( INS_IsMemoryRead(ins) )
				INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(rec_mem_read), IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_END);
			*/
		}
	}
}


// This function is called when the application exits
static VOID Fini(INT32 code, VOID *v)
{
	puts("\n--FiNi--\n");
}

int main(int argc, char * argv[])
{
    // Initialize pin
    if ( PIN_Init(argc, argv) )
		return -1;

	for ( size_t i = 0; i < MAX_THREAD; ++i )
		FuncInfo[i][0].funcAddr = 0xFACEB00C; // for root caller;
	
	// Register Instruction to be called to instrument instructions
    INS_AddInstrumentFunction(Instruction, 0);


    // Register Fini to be called when the application exits
    PIN_AddFiniFunction( Fini, 0 );
    
    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
