#include <iostream>
#include <map>
#include <string>
#include <fstream>

#include "kscope.h"

using namespace std;


bool init_addr_filter( set<ADDRINT> & addrFilter )
{
	// init Addr Filter
	std::ifstream ifs( "config/ksAddrFilter.cfg" );
	if ( ifs.is_open() == false )
	{
		std::cerr << "Fail to open AddrFilter.cfg\n";
		return false;
	}

	std::string s;
	while( ifs )
	{
		std::getline( ifs, s );
		ADDRINT i;
		sscanf( s.c_str(), "%08x\n", &i );
		addrFilter.insert(i);
	}

	printf( "Addr filter size: %d\n", addrFilter.size() );

	return true;
}

bool init_func_filter( set<ADDRINT> & funcFilter )
{
	std::ifstream ifs( "config/ksFuncFilter.cfg" );
	if ( ifs.is_open() == false )
	{
		std::cerr << "Fail to open FuncFilter.cfg\n";
		return false;
	}

	std::string s;
	while( ifs )
	{
		std::getline( ifs, s );
		ADDRINT i;
		sscanf( s.c_str(), "%08x\n", &i );
		funcFilter.insert(i);
	}

	printf( "Func filter size: %d\n", funcFilter.size() );

	return true;
}


bool init_code_section( ADDRINT& codeStartAddr, ADDRINT& codeEndAddr )
{
	// init Addr Filter
	std::ifstream ifs( "config/codeSection.cfg" );
	if ( ifs.is_open() == false )
	{
		std::cerr << "Fail to open codeSection.cfg\n";
		return false;
	}

	std::string s;
	std::getline( ifs, s );
	if ( 0 == sscanf( s.c_str(), "%08x-%08x\n", &codeStartAddr, &codeEndAddr ) )
		return false;

	printf("from %08x to %08x\n", codeStartAddr, codeEndAddr );

	return true;
}

bool init_switch( ADDRINT& switchOnAddr, ADDRINT& switchOffAddr )
{
	// init Addr Filter
	std::ifstream ifs( "config/switch.cfg" );
	if ( ifs.is_open() == false )
	{
		std::cerr << "Fail to open switch.cfg\n";
		return false;
	}

	std::string s;
	std::getline( ifs, s );
	if ( 0 == sscanf( s.c_str(), "%08x-%08x\n", &switchOnAddr, &switchOffAddr ) )
		return false;

	printf("on: %08x; off: %08x\n", switchOnAddr, switchOffAddr );

	return true;

}


bool init_detach_point( ADDRINT& detachPoint )
{
	std::ifstream ifs( "config/detach.cfg" );
	if ( ifs.is_open() == false )
	{
		std::cerr << "Fail to open detach.cfg\n";
		return false;
	}

	std::string s;
	std::getline( ifs, s );
	if ( 0 == sscanf( s.c_str(), "%08x\n", &detachPoint ) )
		return false;

	printf("detachPoint: %08x\n", detachPoint );

	return true;
}