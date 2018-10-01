#include <iostream>
#include <map>
#include <string>
#include <fstream>

#include "kscope.h"

using namespace std;

ConfigReader::ConfigReader()
{
	FileManager LogFile("log/configReader.log", "w");

	codeStartAddr_ = 0xFFFFFFFF;
	codeEndAddr_ = 0xFFFFFFFF;
	switchOnAddr_ = 0xFFFFFFFF;
	switchOffAddr_ = 0xFFFFFFFF;
	detachPoint_ = 0xFFFFFFFF;

	std::ifstream config_fs( "config/kscope.cfg" );
	if ( config_fs.is_open() == false )
	{
		fprintf( LogFile.fp(), "Fail to open config.cfg\n" );
	}
	else
	{
		std::string s;
		do
		{
			std::getline( config_fs, s );

			string::size_type pos = s.find("=");
			if ( pos != std::string::npos && pos > 0 )
			{
				string key = s.substr(0, pos);
				string value = s.substr(pos + 1, std::string::npos);
				configMap_[key] = value;
			}
		}
		while ( s != "====" );

		sscanf( configMap_[string("codeStartAddr")].c_str(), "%08x", &codeStartAddr_ );
		sscanf( configMap_[string("codeEndAddr")].c_str(), "%08x", &codeEndAddr_ );
		codeSectionSize_ = codeEndAddr_ - codeStartAddr_ + 1;
		fprintf( LogFile.fp(), "from %08x to %08x\n", codeStartAddr_, codeEndAddr_ );
		fprintf( LogFile.fp(), "size of code section %u\n", codeSectionSize_ );

		sscanf( configMap_[string("switchOnAddr")].c_str(), "%08x", &switchOnAddr_ );
		sscanf( configMap_[string("switchOffAddr")].c_str(), "%08x", &switchOffAddr_ );
		fprintf( LogFile.fp(), "switch on and off: %08x, %08x\n", switchOnAddr_, switchOffAddr_ );

		sscanf( configMap_[string("detachPoint")].c_str(), "%08x", &detachPoint_ );
		fprintf( LogFile.fp(), "detach at: %08x\n", detachPoint_ );

		sscanf( configMap_[string("instRecNum")].c_str(), "%d", &instRecNum_ );
		fprintf( LogFile.fp(), "instRecNum: %u\n", instRecNum_ );

		sscanf( configMap_[string("threadToMonitor")].c_str(), "%08x", &threadToMonitor_ );
		fprintf( LogFile.fp(), "thread entry: %08x\n", threadToMonitor_ );
	}

	if ( configMap_[string("ksFilter")] == string("on") )
	{
		std::ifstream af_fs( "config/ksAddrFilter.txt" );
		if ( af_fs.is_open() == false )
		{
			fprintf( LogFile.fp(), "Fail to open AddrFilter txt\n" );
		}
		else
		{
			std::string s;
			ADDRINT i;
			while( af_fs )
			{
				std::getline( af_fs, s );
				if ( s.size() >= 8 )
				{
					sscanf( s.c_str(), "%08x\n", &i );
					addrFilter_.insert(i);
				}
 			}
		}
	}
	fprintf( LogFile.fp(), "Addr filter size: %d\n", addrFilter_.size() );
}

bool ConfigReader::is_addrSwc_on()
{
	return configMap_[string("ksSwitch")] == string("on");
}

ADDRINT ConfigReader::get_codeSectionSize()
{
	return codeSectionSize_;
}

ADDRINT ConfigReader::get_codeStartAddr()
{
	return codeStartAddr_;
}

ADDRINT ConfigReader::get_codeEndAddr()
{
	return codeEndAddr_;
}

ADDRINT ConfigReader::get_switchOnAddr()
{
	return switchOnAddr_;
}

ADDRINT ConfigReader::get_switchOffAddr()
{
	return switchOffAddr_;
}

ADDRINT ConfigReader::get_detachPoint()
{
	return detachPoint_;
}

const set<ADDRINT> & ConfigReader::get_addrFilter()
{
	return addrFilter_;
}

bool ConfigReader::in_addr_range(ADDRINT pc)
{
	return ( pc >= codeStartAddr_ && pc <= codeEndAddr_ );
}

bool ConfigReader::in_addr_set(ADDRINT pc)
{
	return ( addrFilter_.find(pc) != addrFilter_.end() );
}

THREADID ConfigReader::get_threadToMonitor()
{
	return threadToMonitor_;
}

size_t ConfigReader::get_instRecNum()
{
	return instRecNum_;
}