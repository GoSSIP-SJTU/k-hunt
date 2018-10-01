#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <vector>
#include <list>

#include "pin.h"
#include "kscope.h"
#include "lzo/minilzo.h"

typedef unsigned char		u1;
typedef unsigned short		u2;
typedef unsigned int		u4;
typedef unsigned long long	u8;

#define forloop(i, start, end) for ( size_t (i) = (start); (i) < (end); ++(i) )
#define forstep(i, start, end, step) for ( size_t (i) = (start); (i) < (end); (i) += (step) )


ConfigReader Config;

static FileManager FpCodePool("./data/bblInst.log", "w");


static VOID bbl_trace(TRACE trace, VOID *v)
{
	// Visit every basic block in the trace
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
		ADDRINT pc = BBL_Address(bbl);
		if ( Config.in_addr_range(pc) )
		{
			for ( INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
			{
				fprintf( FpCodePool.fp(), "%08x|%s\n", INS_Address(ins), INS_Disassemble(ins).c_str() );
			}
			fprintf( FpCodePool.fp(), "----\n" );
			fflush( FpCodePool.fp() );
		}
	}
}


/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

/*
#include "kaleidoscope.h"
#include "memAnalyzer.h"
#include "ksTracer.h"
#include "citation.h"
#include "inputRecorder.h"
#include "bundle.h"
#include "branchTracer.h"
#include "entropy.h"
*/

#include "keyhunter.h"