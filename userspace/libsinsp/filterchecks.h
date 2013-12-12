#pragma once

#ifdef HAS_FILTERING

#define VALIDATE_STR_VAL if(val.length() >= sizeof(m_val_storage)) \
{ \
	throw sinsp_exception("filter error: value too long: " + val); \
}

///////////////////////////////////////////////////////////////////////////////
// Filter check classes
///////////////////////////////////////////////////////////////////////////////

//
// fd checks
//
class sinsp_filter_check_fd : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_FDNUM = 0,
		TYPE_FDTYPE = 1,
		TYPE_FDNAME = 2,
		TYPE_IP = 3,
		TYPE_CLIENTIP = 4,
		TYPE_SERVERIP = 5,
		TYPE_PORT = 6,
		TYPE_CLIENTPORT = 7,
		TYPE_SERVERPORT = 8,
		TYPE_L4PROTO = 9,
		TYPE_SOCKFAMILY = 10,
	};

	enum fd_type
	{
		FDT_NONE,
		FDT_FILE,
		FDT_SOCK,
		FDT_IPV4_SOCK,
		FDT_IPV6_SOCK,
		FDT_UNIX_SOCK,
		FDT_PIPE,
		FDT_EVENT,
		FDT_SIGNALFD,
		FDT_EVENTPOLL,
		FDT_INOTIFY,
		FDT_TIMERFD
	};

	sinsp_filter_check_fd();
	sinsp_filter_check* allocate_new();
	int32_t parse_field_name(const char* str);
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len);
	uint8_t* extract_fdtype(sinsp_fdinfo* fdinfo);
	bool compare_ip(sinsp_evt *evt);
	bool compare_port(sinsp_evt *evt);
	bool compare(sinsp_evt *evt);

	sinsp_threadinfo* m_tinfo;
	sinsp_fdinfo* m_fdinfo;
	string m_fdname;
	fd_type m_fd_type;
};

//
// thread checks
//
class sinsp_filter_check_thread : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_PID = 0,
		TYPE_EXE = 1,
		TYPE_COMM = 2,
		TYPE_ARGS = 3,
		TYPE_CWD = 4,
		TYPE_NCHILDS = 5,
		TYPE_TID = 6,
		TYPE_ISMAINTHREAD = 7,
	};

	sinsp_filter_check_thread();
	sinsp_filter_check* allocate_new();
	int32_t parse_field_name(const char* str);
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len);

	// XXX this is overkill and wasted for most of the fields.
	// It could be optimized by dynamically allocating the right amount
	// of memory, but we don't care for the moment since we expect filters 
	// to be pretty small.
	uint32_t m_tbool;
	string m_tstr;
	uint64_t m_u64val;
};

//
// event checks
//
class sinsp_filter_check_event : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_NUMBER = 0,
		TYPE_TS = 1,
		TYPE_TS_S = 2,
		TYPE_TS_NS = 3,
		TYPE_RELTS = 4,
		TYPE_RELTS_S = 5,
		TYPE_RELTS_NS = 6,
		TYPE_LATENCY = 7,
		TYPE_DIR = 8,
		TYPE_NAME = 9,
		TYPE_CPU = 10,
		TYPE_ARGS = 11,
		TYPE_ARGSTR = 12,
		TYPE_ARGRAW = 13,
		TYPE_RES = 14,
	};

	sinsp_filter_check_event();
	sinsp_filter_check* allocate_new();
	int32_t parse_field_name(const char* str);
	void parse_filter_value(const char* str);
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len);
	bool compare(sinsp_evt *evt);
	char* tostring(sinsp_evt* evt);

	uint64_t m_first_ts;
	uint64_t m_u64val;
	string m_strstorage;
	string m_argname;
	int32_t m_argid;
	const ppm_param_info* m_arginfo;
	//
	// Note: this copy of the field is used by some fields, like TYPE_ARGS and 
	// TYPE_RESARG, that need to do on the fly type customization
	//
	filtercheck_field_info m_customfield;

private:
	int32_t extract_arg(string fldname, string val, OUT const struct ppm_param_info** parinfo);
};

//
// user checks
//
class sinsp_filter_check_user : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_UID = 0,
		TYPE_NAME = 1,
		TYPE_HOMEDIR = 2,
		TYPE_SHELL = 3,
	};

	sinsp_filter_check_user();
	sinsp_filter_check* allocate_new();
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len);

	uint32_t m_uid;
	string m_strval;
};

//
// group checks
//
class sinsp_filter_check_group : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_GID,
		TYPE_NAME,
	};

	sinsp_filter_check_group();
	sinsp_filter_check* allocate_new();
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len);

	uint32_t m_gid;
	string m_name;
};

//
// Fake filter check used by the event formatter to render format text
//
class rawstring_check : public sinsp_filter_check
{
public:
	rawstring_check(string text);
	sinsp_filter_check* allocate_new();
	void set_text(string text);
	int32_t parse_field_name(const char* str);
	void parse_filter_value(const char* str);
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len);

	// XXX this is overkill and wasted for most of the fields.
	// It could be optimized by dynamically allocating the right amount
	// of memory, but we don't care for the moment since we expect filters 
	// to be pretty small.
	string m_text;
	uint32_t m_text_len;
};

#endif // HAS_FILTERING
