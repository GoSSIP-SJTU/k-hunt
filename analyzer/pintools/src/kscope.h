#ifndef _KSCOPE_H_
#define _KSCOPE_H_

#include "pin.h"
#include <vector>
#include <map>
#include <set>

typedef unsigned char uint8_t;
typedef unsigned int uint32_t;

const static size_t REG_SIZE = 4; // for 32-bit platform

static const size_t WRITE_BUF_MAX_LEN = 64 * 32 * 0x1000;

class FileManager
{
public:
	FileManager( const char * const fileName, const char * const mode );
	~FileManager();
	FILE * fp();

private:
	FILE * file_;
};

class Compressor
{
public:
	Compressor();
	~Compressor();

	bool set_trace_file( char * recordFile );
	void flush();
	void save_data( void * data, size_t inLen);
	int compress_and_write();

private:
	unsigned char buffer_[WRITE_BUF_MAX_LEN];
	unsigned char lzoData_[WRITE_BUF_MAX_LEN];
	size_t counter_;
	FILE * traceFile_;
	FileManager logFile_;
	static bool toInitFlag_;
};


class Bundler
{
public:
	void init( ADDRINT base, size_t size )
	{
		baseAddr_ = base;
		instBundler_ = vector< set<ADDRINT> >(size);
	}

	void add_record( ADDRINT pc, ADDRINT memAddr )
	{
		instBundler_[pc - baseAddr_].insert(memAddr);
	}

	void output_log( FILE * fp )
	{
		for ( size_t i = 0; i < instBundler_.size(); ++i )
		{
			if ( instBundler_[i].size() != 0 )
				fprintf( fp, "%08x -- %u\n", i + baseAddr_, instBundler_[i].size() );
		}
	}

private:
	vector< set<ADDRINT> > instBundler_;
	ADDRINT baseAddr_;
};


class InstCounter
{
public:
	void init( ADDRINT base, size_t size )
	{
		baseAddr_ = base;
		instRecCounter_ = vector<size_t>(size);
	}

	size_t inst_record_num( ADDRINT pc )
	{
		return instRecCounter_[pc - baseAddr_];
	}

	void add_record( ADDRINT pc )
	{
		++instRecCounter_[pc - baseAddr_];
	}

	void clean()
	{
		instRecCounter_ = vector<size_t>(instRecCounter_.size());
	}

private:
	ADDRINT baseAddr_;
	vector<size_t> instRecCounter_;
};


#include "configReader.h"

bool init_Interval( size_t& interval );
bool init_code_section( ADDRINT& codeStartAddr, ADDRINT& codeEndAddr );
bool init_func_filter( std::set<ADDRINT> & funcFilter );
bool init_addr_filter( std::set<ADDRINT> & addrFilter );
bool init_switch( ADDRINT& switchOnAddr, ADDRINT& switchOffAddr );
bool init_detach_point( ADDRINT& detachPoint );

int		compress_and_write				( FILE * fp, void * data, size_t inLen );
void	compress_and_write_with_buffer	( FILE * fp, void * data, size_t inLen );




#endif

