#pragma once

#ifdef HAS_FILTERING

enum boolop
{
	BO_NONE = 0,
	BO_NOT = 1,
	BO_OR = 2,
	BO_AND = 4,
	BO_ORNOT = 3,
	BO_ANDNOT = 5,
};

///////////////////////////////////////////////////////////////////////////////
// Filter check classes
///////////////////////////////////////////////////////////////////////////////

//
// The filter check interface
// NOTE: in order to add a new type of filter check, you need to add a class for
//       it and then add it to sinsp_filter::parse_check.
//
class sinsp_filter_check
{
public:
	sinsp_filter_check();
	virtual ~sinsp_filter_check()
	{
	}

	virtual void parse_operand1(string val)
	{
		return;
	}
	virtual void parse_operand2(string val)
	{
		return;
	}
	virtual bool run(sinsp_evt *evt) = 0;

	bool compare(ppm_cmp_operator op, ppm_param_type type, void* operand1, void* operand2);

	boolop m_boolop;
	ppm_cmp_operator m_cmpop;
};

//
// comm check
//
class sinsp_filter_check_comm : public sinsp_filter_check
{
public:
	void parse_operand2(string val);
	bool run(sinsp_evt *evt);
	static bool recognize_operand(string operand);

	string m_comm;
};

//
// numeric tid check
//
class sinsp_filter_check_tid : public sinsp_filter_check
{
public:
	void parse_operand2(string val);
	bool run(sinsp_evt *evt);
	static bool recognize_operand(string operand);

	int64_t m_tid;
};

//
// numeric fd check
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

	static bool recognize_operand(string operand);
	void parse_operand1(string val);
	void parse_operand2(string val);
	bool run(sinsp_evt *evt);
	bool check_fdtype(sinsp_fdinfo* fdinfo);

	check_type m_type;
	int64_t m_fd;
	string m_fdname;
	fd_type m_fd_type;
	uint32_t m_ip;
	uint16_t m_port;
};


#endif // HAS_FILTERING
