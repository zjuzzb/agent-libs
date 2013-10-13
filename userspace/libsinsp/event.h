#pragma once

typedef class sinsp sinsp;
typedef class sinsp_threadinfo sinsp_threadinfo;
typedef class sinsp_fdinfo sinsp_fdinfo;

///////////////////////////////////////////////////////////////////////////////
// Event arguments
///////////////////////////////////////////////////////////////////////////////

//
// tostring() argument categories
//
typedef enum event_property_category
{
	ETSC_NONE = 0,
	ETSC_RAWSTRING,		// used when formatting events into strings
	// Event fields
	ETSC_NUMBER,
	ETSC_TS,
	ETSC_RELTS,
	ETSC_RELTS_S,
	ETSC_RELTS_NS,
	ETSC_DIRECTION,
	ETSC_NAME,
	ETSC_CPU,
	ETSC_ARGS,
	ETSC_RES,
	// FD fields
	ETSC_FD_NUM,
	ETSC_FD_TYPE,
	ETSC_FD_NAME,
	ETSC_FD_IP,
	ETSC_FD_CLIENTADDR,
	ETSC_FD_SERVERADDR,
	ETSC_FD_PORT,
	ETSC_FD_CLIENTPORT,
	ETSC_FD_SERVERPORT,
	ETSC_FD_L4PROTO,
	ETSC_FD_SOCKFAMILY,
	// thread fields
	ETSC_TH_TID,
	ETSC_TH_PID,
	ETSC_TH_EXE,
	ETSC_TH_COMM,
	ETSC_TH_ARGS,
	ETSC_TH_CWD,
	ETSC_TH_NCHILDS,
	ETSC_TH_ISMAINTHREAD,
	// user fields
	ETSC_U_UID,
	ETSC_U_USERNAME,
	ETSC_U_HOMEDIR,
	ETSC_U_SHELL,
	// group fields
	ETSC_G_GID,
	ETSC_G_GROUPNAME,
}event_property_category;

typedef enum event_property_flags
{
	EPF_NONE = 0,
	EPF_FILTER_ONLY, // this argument can only be used as a filter
	EPF_PRINT_ONLY, // this argument can only be used in the tostring() call
}event_property_flags;

typedef struct event_property_info
{
	event_property_category m_category;
	ppm_param_type m_type;
	event_property_flags m_flags;
	ppm_print_format m_print_format;
	char m_prefix[16];
	char m_name[64];
	char m_description[1024];
}event_property_info;

///////////////////////////////////////////////////////////////////////////////
// Wrapper that exports the libscap event tables
///////////////////////////////////////////////////////////////////////////////
class sinsp_evttables
{
public:
	const struct ppm_event_info* m_event_info;
	const struct ppm_syscall_desc* m_syscall_info_table;
};

///////////////////////////////////////////////////////////////////////////////
// Event parameter wrapper class
///////////////////////////////////////////////////////////////////////////////
class SINSP_PUBLIC sinsp_evt_param
{
public:
	void init(char* valptr, uint16_t len);
	char* m_val;
	uint16_t m_len;
};

///////////////////////////////////////////////////////////////////////////////
// information about a tostring() piece 
///////////////////////////////////////////////////////////////////////////////
class tostring_entry
{
public:
	tostring_entry(event_property_category cat, string data)
	{
		m_cat = cat;
		m_data = data;
	}

	event_property_category m_cat;
	string m_data;
};

///////////////////////////////////////////////////////////////////////////////
// Event class
///////////////////////////////////////////////////////////////////////////////
class SINSP_PUBLIC sinsp_evt
{
public:
	//
	// How to render an event parameter to string
	//
	enum param_fmt
	{
		PF_NORMAL,	// Normal screen output
		PF_JSON,	// Json formatting
		PF_SIMPLE,	// Reduced output, e.g. not type character for FDs
	};

	//
	// Event subcategory specialization based on the fd type
	//
	enum subcategory
	{
		SC_UNKNOWN = 0,
		SC_NONE = 1,
		SC_OTHER = 2,
		SC_FILE = 3,
		SC_NET = 4,
		SC_IPC = 5,
	};

	//
	// Information regarding an event category, enriched with fd state
	//
	struct category
	{
		ppm_event_category m_category;	// Event category from the driver
		subcategory m_subcategory;		// Domain for IO and wait events
	};

	sinsp_evt();
	sinsp_evt(sinsp* inspector);
	~sinsp_evt();

	void init();
	void init(uint8_t* evdata, uint16_t cpuid);
	uint64_t get_num();
	int16_t get_cpuid();
	uint16_t get_type();
	ppm_event_flags get_flags();
	uint64_t get_ts();
	const char* get_name();
	event_direction get_direction();
	int64_t get_tid();
	void set_iosize(uint32_t size);
	uint32_t get_iosize();
	sinsp_threadinfo* get_thread_info(bool query_os_if_not_found = false);
	sinsp_fdinfo* get_fd_info();
	uint32_t get_num_params();
	sinsp_evt_param* get_param(uint32_t id);
	const char* get_param_name(uint32_t id);
	const struct ppm_param_info* get_param_info(uint32_t id);
	const char* get_param_as_str(uint32_t id, OUT const char** resolved_str, param_fmt fmt = PF_NORMAL);
	string get_param_value_str(const char* name, bool resolved = true);
	string get_param_value_str(string& name, bool resolved = true);
	const char* get_param_value_str(const char* name, OUT const char** resolved_str);
	void get_category(OUT sinsp_evt::category* cat);

	uint8_t* get_property_raw(event_property_category prop);
	void get_property_as_string(event_property_category prop, OUT char** val);
	void set_tostring_format(const string& fmt);
	void tostring(OUT string* res);
private:
	void load_params();
	string get_param_value_str(uint32_t id, bool resolved);

	sinsp* m_inspector;
	scap_evt* m_pevt;
	uint16_t m_cpuid;
	uint64_t m_evtnum;
	bool m_params_loaded;
	const struct ppm_event_info* m_info;
	vector<sinsp_evt_param> m_params;
	char m_paramstr_storage[1024];
	char m_resolved_paramstr_storage[1024];
	sinsp_threadinfo* m_tinfo;
	sinsp_fdinfo* m_fdinfo;
	uint32_t m_iosize;
	int32_t m_errorcode;
#ifdef _DEBUG
	bool m_filtered_out;
#endif
	vector<tostring_entry> m_tostring_tokens;

	friend class sinsp;
	friend class sinsp_parser;
	friend class sinsp_threadinfo;
	friend class sinsp_analyzer;
	friend class sinsp_filter_check_event;
};
