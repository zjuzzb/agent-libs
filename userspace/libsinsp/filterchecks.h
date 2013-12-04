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
	int32_t parse_field_name(const char* str);
	uint8_t* extract(sinsp_evt *evt);
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
		TYPE_TID = 0,
		TYPE_PID = 1,
		TYPE_EXE = 2,
		TYPE_COMM = 3,
		TYPE_ARGS = 4,
		TYPE_CWD = 5,
		TYPE_NCHILDS = 6,
		TYPE_ISMAINTHREAD = 7,
	};

	sinsp_filter_check_thread();
	int32_t parse_field_name(const char* str);
	uint8_t* extract(sinsp_evt *evt);

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
		TYPE_DIR = 7,
		TYPE_NAME = 8,
		TYPE_CPU = 9,
		TYPE_ARGS = 10,
		TYPE_RESARG = 11,
		TYPE_ARG = 12,
		TYPE_RES = 13,
	};

	sinsp_filter_check_event();
	int32_t parse_field_name(const char* str);
	void parse_filter_value(const char* str);
	uint8_t* extract(sinsp_evt *evt);
	bool compare(sinsp_evt *evt);

	uint64_t m_first_ts;
	uint64_t m_u64val;
	string m_strstorage;
	string m_argname;
	int32_t m_argid;
	const ppm_param_info* m_arginfo;

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
	uint8_t* extract(sinsp_evt *evt);

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
		TYPE_NONE,
		TYPE_GID,
		TYPE_NAME,
	};

	sinsp_filter_check_group();
	uint8_t* extract(sinsp_evt *evt);

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
	void set_text(string text);
	int32_t parse_field_name(const char* str);
	void parse_filter_value(const char* str);
	uint8_t* extract(sinsp_evt *evt);

	// XXX this is overkill and wasted for most of the fields.
	// It could be optimized by dynamically allocating the right amount
	// of memory, but we don't care for the moment since we expect filters 
	// to be pretty small.
	string m_text;
};

#endif // HAS_FILTERING
