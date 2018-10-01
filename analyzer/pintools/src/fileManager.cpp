#include <iostream>
#include "kscope.h"

FileManager::FileManager( const char * const fileName, const char * const mode )
{
	file_ = fopen( fileName, mode );
	if ( NULL == file_ )
		throw std::runtime_error("cannot open file");
	fclose(file_);
	file_ = fopen( fileName, mode );
}
	
FileManager::~FileManager()
{
	fclose(file_);
}

FILE * FileManager::fp()
{
	return file_; 
}
