#include <iostream>

#include "lzo/minilzo.h"
#include "kscope.h"

bool Compressor::toInitFlag_ = false;

/* Work-memory needed for compression. Allocate memory in units
 * of 'lzo_align_t' (instead of 'char') to make sure it is properly aligned.
 */

#define HEAP_ALLOC(var,size) \
    lzo_align_t __LZO_MMODEL var [ ((size) + (sizeof(lzo_align_t) - 1)) / sizeof(lzo_align_t) ]

Compressor::Compressor() : logFile_("data/lzo.log", "w")
{
	if (toInitFlag_ == false)
	{
		if ( lzo_init() != LZO_E_OK )
		{
			fprintf( logFile_.fp(), "internal error - lzo_init() failed !!!\n");
			fprintf( logFile_.fp(), "(this usually indicates a compiler bug - try recompiling\nwithout optimizations, and enable '-DLZO_DEBUG' for diagnostics)\n");
			fflush(logFile_.fp());
			throw runtime_error("lzo_init() failed");
		}
		toInitFlag_ = true;
	}

	traceFile_ = NULL;
}
	
Compressor::~Compressor()
{
	if ( traceFile_ )
	{
		this->flush();
		fclose(traceFile_);
	}
}

bool Compressor::set_trace_file( char * recordFile )
{
	traceFile_ = fopen( recordFile, "wb" );
	return traceFile_ != NULL;
}

void Compressor::flush()
{
	compress_and_write();
	counter_ = 0;
}

void Compressor::save_data( void * data, size_t inLen)
{
	static PIN_LOCK sherlock;
	PIN_GetLock(&sherlock, 1);
	
	if ( inLen + counter_ > WRITE_BUF_MAX_LEN )
	{
		compress_and_write();
		counter_ = 0;
	}

	memcpy( buffer_ + counter_, data , inLen );
	counter_ += inLen;
	PIN_ReleaseLock(&sherlock);
}

int Compressor::compress_and_write()
{
	HEAP_ALLOC(wrkmem, LZO1X_1_MEM_COMPRESS);
	
	lzo_uint outLen;

	if (lzo1x_1_compress(buffer_, counter_, lzoData_, &outLen, wrkmem) != LZO_E_OK)
	{
		/* this should NEVER happen */
		// fprintf( logFile_.fp(), "internal error - compression failed: %d\n", r );
		return -1;
	}

	if (outLen >= counter_)
	{
		fprintf( logFile_.fp(), "This block contains incompressible data.\n" );
	}
	else
	{
		fwrite( &outLen, sizeof(int), 1, traceFile_ );
		fwrite( lzoData_, 1, outLen, traceFile_ );
		fflush( traceFile_ );

		fprintf( logFile_.fp(), "in: %u, out: %lu\n", counter_, outLen );
	}

	return outLen;
}
