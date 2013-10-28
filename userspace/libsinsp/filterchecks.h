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
		TYPE_NONE,
		TYPE_FDNUM,
		TYPE_FDTYPE,
		TYPE_FDNAME,
		TYPE_IP,
		TYPE_CLIENTIP,
		TYPE_SERVERIP,
		TYPE_PORT,
		TYPE_CLIENTPORT,
		TYPE_SERVERPORT,
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

	filter_check_fields get_filelds();
	static bool recognize_operand(string operand);
	void parse_field_name(string val);
	void parse_filter_value(string val);
	uint8_t* extract(sinsp_evt *evt);
	bool compare(sinsp_evt *evt);
	bool check_fdtype(sinsp_fdinfo* fdinfo);

	check_type m_type;
	int64_t m_fd;
	string m_fdname;
	fd_type m_fd_type;
	uint32_t m_ip;
	uint16_t m_port;
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
		TYPE_COMM = 2,
		TYPE_EXE = 3,
		TYPE_ARGS = 4,
		TYPE_CWD = 5,
		TYPE_NCHILDS = 6,
		TYPE_ISMAINTHREAD = 7,
	};

	filter_check_fields get_filelds();
	static bool recognize_operand(string operand);
	void parse_field_name(string val);
	void parse_filter_value(string val);
	uint8_t* extract(sinsp_evt *evt);
	bool compare(sinsp_evt *evt);

	check_type m_type;
	// XXX this is overkill and wasted for most of the fields.
	// It could be optimized by dynamically allocating the right amount
	// of memory, but we don't care for the moment since we expect filters 
	// to be pretty small.
	uint8_t m_val_storage[1024];
	bool m_tbool;
};

//
// event checks
//
class sinsp_filter_check_event : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_NONE,
		TYPE_TS,
		TYPE_NAME,
		TYPE_NUMBER,
		TYPE_CPU,
		TYPE_ARGS
	};

	filter_check_fields get_filelds();
	static bool recognize_operand(string operand);
	void parse_field_name(string val);
	void parse_filter_value(string val);
	uint8_t* extract(sinsp_evt *evt);
	bool compare(sinsp_evt *evt);

	check_type m_type;
	ppm_param_type m_arg_type;
	uint64_t m_u64val;
	int64_t m_d64val;
	string m_strval;
	uint16_t m_evttype;
	int16_t m_cpuid;
	string m_argname;
};

//
// user checks
//
class sinsp_filter_check_user : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_NONE,
		TYPE_UID,
		TYPE_NAME,
		TYPE_HOMEDIR,
		TYPE_SHELL,
	};

	filter_check_fields get_filelds();
	static bool recognize_operand(string operand);
	void parse_field_name(string val);
	void parse_filter_value(string val);
	uint8_t* extract(sinsp_evt *evt);
	bool compare(sinsp_evt *evt);

	check_type m_type;
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

	filter_check_fields get_filelds();
	static bool recognize_operand(string operand);
	void parse_field_name(string val);
	void parse_filter_value(string val);
	uint8_t* extract(sinsp_evt *evt);
	bool compare(sinsp_evt *evt);

	check_type m_type;
	uint32_t m_gid;
	string m_name;
};

#endif // HAS_FILTERING
