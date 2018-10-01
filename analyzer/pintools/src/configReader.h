
class ConfigReader
{
public:
	ConfigReader();

	ADDRINT get_codeStartAddr();
	ADDRINT get_codeEndAddr();
	ADDRINT get_switchOnAddr();
	ADDRINT get_switchOffAddr();
	ADDRINT get_detachPoint();
	THREADID get_threadToMonitor();
	size_t get_instRecNum();
	size_t get_codeSectionSize();
	const set<ADDRINT> & get_addrFilter();

	bool in_addr_range	(ADDRINT pc);
	bool in_addr_set	(ADDRINT pc);
	bool is_addrSwc_on		();

private:
	ADDRINT codeStartAddr_;
	ADDRINT codeEndAddr_;
	ADDRINT switchOnAddr_;
	ADDRINT switchOffAddr_;
	ADDRINT detachPoint_;
	size_t codeSectionSize_;
	THREADID threadToMonitor_;
	size_t instRecNum_;
	set<ADDRINT> addrFilter_;
	map<string, string> configMap_;
};

