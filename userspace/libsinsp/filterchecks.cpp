#include "sinsp.h"
#include "sinsp_int.h"

#ifdef HAS_FILTERING
#include "filter.h"
#include "filterchecks.h"

extern sinsp_evttables g_infotables;

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_check_fd implementation
///////////////////////////////////////////////////////////////////////////////
const event_field_info sinsp_filter_check_fd_fields[] =
{
	{PT_INT64, EPF_NONE, PF_DEC, "num", "the unique number identifying the file descriptor."},
	{PT_UINT32, EPF_NONE, PF_DEC, "type", "type of FD. Can be one of XXX."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "name", "FD full name. If the fd is a file, this field contains the full path. If the FD is a socket, this field contain the connection tuple."},
	{PT_SOCKADDR, EPF_FILTER_ONLY, PF_NA, "addr", "matches the ip address (client or server) of the fd."},
	{PT_SOCKADDR, EPF_NONE, PF_NA, "caddr", "source IP address."},
	{PT_SOCKADDR, EPF_NONE, PF_NA, "saddr", "destination IP address."},
	{PT_UINT64, EPF_FILTER_ONLY, PF_DEC, "port", "matches the port (client or server) of the fd."},
	{PT_PORT, EPF_NONE, PF_DEC, "cport", "source TCP/UDP port."},
	{PT_PORT, EPF_NONE, PF_DEC, "sport", "destination TCP/UDP port."},
	{PT_UINT8, EPF_NONE, PF_DEC, "l4proto", "IP protocol number."},
	{PT_SOCKFAMILY, EPF_NONE, PF_DEC, "sockfamily", "the socket family for socket events. Can be 'ip' or 'unix'."},
};

sinsp_filter_check_fd::sinsp_filter_check_fd()
{
	m_info.m_name = "fd";

	m_info.m_fields = sinsp_filter_check_fd_fields;
	m_info.m_nfiedls = sizeof(sinsp_filter_check_fd_fields) / sizeof(sinsp_filter_check_fd_fields[0]);
}

int32_t sinsp_filter_check_fd::parse_field_name(const char* str)
{
/*
	m_type = TYPE_NONE;

	if(val.substr(0, string("fd").length()) == "fd")
	{
		vector<string> components = sinsp_split(val, '.');

		if(components.size() == 1)
		{
			m_type = TYPE_FDNUM;
			return;
		}
		else if(components.size() == 2)
		{
			if(components[1] == "name")
			{
				m_type = TYPE_FDNAME;
				return;
			}
			else if(components[1] == "type")
			{
				m_type = TYPE_FDTYPE;
				return;
			}
			else if(components[1] == "ip")
			{
				m_type = TYPE_IP;
				return;
			}
			else if(components[1] == "clientip")
			{
				m_type = TYPE_CLIENTIP;
				return;
			}
			else if(components[1] == "serverip")
			{
				m_type = TYPE_SERVERIP;
				return;
			}
			else if(components[1] == "port")
			{
				m_type = TYPE_PORT;
				return;
			}
			else if(components[1] == "clientport")
			{
				m_type = TYPE_CLIENTPORT;
				return;
			}
			else if(components[1] == "serverport")
			{
				m_type = TYPE_SERVERPORT;
				return;
			}
		}
	}

	throw sinsp_exception("filter error: unrecognized field " + val);
*/
	return -1;
}

void sinsp_filter_check_fd::parse_filter_value(const char* str)
{
/*
	switch(m_type)
	{
	case TYPE_FDNUM:
		m_fd = sinsp_numparser::parsed64(val);
		break;
	case TYPE_FDNAME:
		m_fdname = val;
		break;
	case TYPE_FDTYPE:
		if(val == "file")
		{
			m_fd_type = FDT_FILE;
			return;
		}
		else if(val == "socket")
		{
			m_fd_type = FDT_SOCK;
			return;
		}
		else if(val == "ipv4socket")
		{
			m_fd_type = FDT_IPV4_SOCK;
			return;
		}
		else if(val == "ipv6socket")
		{
			m_fd_type = FDT_IPV6_SOCK;
			return;
		}
		else if(val == "unixsocket")
		{
			m_fd_type = FDT_UNIX_SOCK;
			return;
		}
		else if(val == "pipe")
		{
			m_fd_type = FDT_PIPE;
			return;
		}
		else if(val == "event")
		{
			m_fd_type = FDT_EVENT;
			return;
		}
		else if(val == "signalfd")
		{
			m_fd_type = FDT_SIGNALFD;
			return;
		}
		else if(val == "eventpoll")
		{
			m_fd_type = FDT_EVENTPOLL;
			return;
		}
		else if(val == "inotify")
		{
			m_fd_type = FDT_INOTIFY;
			return;
		}
		else if(val == "timerfd")
		{
			m_fd_type = FDT_TIMERFD;
			return;
		}
		else
		{
			throw sinsp_exception("filter error: unsupported fd type " + val);
		}
		break;
	case TYPE_IP:
	case TYPE_CLIENTIP:
	case TYPE_SERVERIP:
		{
			if(inet_pton(AF_INET, val.c_str(), &m_ip) != 1)
			{
				throw sinsp_exception("filter error: malformed IP address " + val);
			}
		}
		break;
	case TYPE_PORT:
	case TYPE_CLIENTPORT:
	case TYPE_SERVERPORT:
		m_port = sinsp_numparser::parseu32(val);
		break;
	default:
		ASSERT(false);
	}
*/
}

const event_field_info* sinsp_filter_check_fd::get_field_info()
{
	return NULL;
}

bool sinsp_filter_check_fd::check_fdtype(sinsp_fdinfo* fdinfo)
{
	scap_fd_type evt_type = fdinfo->m_type;

	switch(m_fd_type)
	{
	case FDT_FILE:
		if(evt_type == SCAP_FD_FILE || evt_type == SCAP_FD_DIRECTORY)
		{
			return true;
		}
		break;
	case FDT_SOCK:
		if(evt_type == SCAP_FD_IPV4_SOCK || evt_type == SCAP_FD_IPV6_SOCK ||
			 evt_type == SCAP_FD_IPV4_SERVSOCK || evt_type == SCAP_FD_IPV6_SERVSOCK || evt_type == SCAP_FD_UNIX_SOCK)
		{
			return true;
		}
		break;
	case FDT_IPV4_SOCK:
		if(evt_type == SCAP_FD_IPV4_SOCK || evt_type == SCAP_FD_IPV4_SERVSOCK)
		{
			return true;
		}
		break;
	case FDT_IPV6_SOCK:
		if(evt_type == SCAP_FD_IPV6_SOCK || evt_type == SCAP_FD_IPV6_SERVSOCK)
		{
			return true;
		}
		break;
	case FDT_UNIX_SOCK:
		if(evt_type == SCAP_FD_UNIX_SOCK)
		{
			return true;
		}
		break;
	case FDT_PIPE:
		if(evt_type == SCAP_FD_FIFO)
		{
			return true;
		}
		break;
	case FDT_EVENT:
		if(evt_type == SCAP_FD_EVENT)
		{
			return true;
		}
		break;
	case FDT_SIGNALFD:
		if(evt_type == SCAP_FD_SIGNALFD)
		{
			return true;
		}
		break;
	case FDT_EVENTPOLL:
		if(evt_type == SCAP_FD_EVENTPOLL)
		{
			return true;
		}
		break;
	case FDT_INOTIFY:
		if(evt_type == SCAP_FD_INOTIFY)
		{
			return true;
		}
		break;
	case FDT_TIMERFD:
		if(evt_type == SCAP_FD_TIMERFD)
		{
			return true;
		}
		break;
	default:
		ASSERT(false);
	}

	return false;
}

uint8_t* sinsp_filter_check_fd::extract(sinsp_evt *evt)
{
	ASSERT(false);
	return NULL;
}

bool sinsp_filter_check_fd::compare(sinsp_evt *evt)
{
	ASSERT(evt);
	sinsp_threadinfo* tinfo;
	sinsp_fdinfo* fdinfo;
	ppm_event_flags eflags = evt->get_flags();

	//
	// Make sure this is an event that creates or consumes an fd
	//
	if(eflags & (EF_CREATES_FD | EF_USES_FD | EF_DESTROYS_FD))
	{
		//
		// This is an fd-related event, get the thread info and the fd info
		//
		tinfo = evt->get_thread_info();
		if(tinfo == NULL)
		{
			return false;
		}

		fdinfo = evt->get_fd_info();

		if(fdinfo == NULL && tinfo->m_lastevent_fd != -1)
		{
			fdinfo = tinfo->get_fd(tinfo->m_lastevent_fd);
		}
	}
	else
	{
		return false;
	}

	switch(m_type)
	{
	case TYPE_FDNUM:
		if(flt_compare(m_cmpop, PT_PID, &tinfo->m_lastevent_fd, &m_fd) == true)
		{
			return true;
		}

		break;
	case TYPE_FDNAME:
		if(fdinfo != NULL && flt_compare(m_cmpop, 
			PT_CHARBUF, 
			(void*)fdinfo->m_name.c_str(), (void*)m_fdname.c_str()) == true)
		{
			return true;
		}

		break;
	case TYPE_FDTYPE:
		if(fdinfo != NULL)
		{
			return check_fdtype(fdinfo);
		}

		break;
	case TYPE_IP:
		if(fdinfo != NULL)
		{
			scap_fd_type evt_type = fdinfo->m_type;

			if(evt_type == SCAP_FD_IPV4_SOCK)
			{
				if(fdinfo->m_info.m_ipv4info.m_fields.m_sip == m_ip ||
					fdinfo->m_info.m_ipv4info.m_fields.m_dip == m_ip)
				{
					return true;
				}
			}
			else if(evt_type == SCAP_FD_IPV4_SERVSOCK)
			{
				if(fdinfo->m_info.m_ipv4serverinfo.m_ip == m_ip)
				{
					return true;
				}
			}
		}

		break;
	case TYPE_CLIENTIP:
		if(fdinfo != NULL)
		{
			scap_fd_type evt_type = fdinfo->m_type;

			if(evt_type == SCAP_FD_IPV4_SOCK)
			{
				if(fdinfo->m_info.m_ipv4info.m_fields.m_sip == m_ip)
				{
					return true;
				}
			}
		}

		break;
	case TYPE_SERVERIP:
		if(fdinfo != NULL)
		{
			scap_fd_type evt_type = fdinfo->m_type;

			if(evt_type == SCAP_FD_IPV4_SOCK)
			{
				if(fdinfo->m_info.m_ipv4info.m_fields.m_dip == m_ip)
				{
					return true;
				}
			}
			else if(evt_type == SCAP_FD_IPV4_SERVSOCK)
			{
				if(fdinfo->m_info.m_ipv4serverinfo.m_ip == m_ip)
				{
					return true;
				}
			}
		}

		break;
	case TYPE_PORT:
		if(fdinfo != NULL)
		{
			scap_fd_type evt_type = fdinfo->m_type;

			if(evt_type == SCAP_FD_IPV4_SOCK)
			{
				if(fdinfo->m_info.m_ipv4info.m_fields.m_sport == m_port ||
					fdinfo->m_info.m_ipv4info.m_fields.m_dport == m_port)
				{
					return true;
				}
			}
			else if(evt_type == SCAP_FD_IPV4_SERVSOCK)
			{
				if(fdinfo->m_info.m_ipv4serverinfo.m_port == m_port)
				{
					return true;
				}
			}
			else if(evt_type == SCAP_FD_IPV6_SOCK)
			{
				if(fdinfo->m_info.m_ipv6info.m_fields.m_sport == m_port ||
					fdinfo->m_info.m_ipv6info.m_fields.m_dport == m_port)
				{
					return true;
				}
			}
			else if(evt_type == SCAP_FD_IPV6_SERVSOCK)
			{
				if(fdinfo->m_info.m_ipv6serverinfo.m_port == m_port)
				{
					return true;
				}
			}
		}
	case TYPE_CLIENTPORT:
		if(fdinfo != NULL)
		{
			scap_fd_type evt_type = fdinfo->m_type;

			if(evt_type == SCAP_FD_IPV4_SOCK)
			{
				if(fdinfo->m_info.m_ipv4info.m_fields.m_sport)
				{
					return true;
				}
			}
			else if(evt_type == SCAP_FD_IPV6_SOCK)
			{
				if(fdinfo->m_info.m_ipv6info.m_fields.m_sport == m_port)
				{
					return true;
				}
			}
		}
	case TYPE_SERVERPORT:
		if(fdinfo != NULL)
		{
			scap_fd_type evt_type = fdinfo->m_type;

			if(evt_type == SCAP_FD_IPV4_SOCK)
			{
				if(fdinfo->m_info.m_ipv4info.m_fields.m_dport == m_port)
				{
					return true;
				}
			}
			else if(evt_type == SCAP_FD_IPV4_SERVSOCK)
			{
				if(fdinfo->m_info.m_ipv4serverinfo.m_port == m_port)
				{
					return true;
				}
			}
			else if(evt_type == SCAP_FD_IPV6_SOCK)
			{
				if(fdinfo->m_info.m_ipv6info.m_fields.m_dport == m_port)
				{
					return true;
				}
			}
			else if(evt_type == SCAP_FD_IPV6_SERVSOCK)
			{
				if(fdinfo->m_info.m_ipv6serverinfo.m_port == m_port)
				{
					return true;
				}
			}
		}

		break;

	default:
		ASSERT(false);
	}

	return false;
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_check_thread implementation
///////////////////////////////////////////////////////////////////////////////
const event_field_info sinsp_filter_check_thread_fields[] =
{
	{PT_INT64, EPF_NONE, PF_DEC, "tid", "the id of the thread generating the event."},
	{PT_INT64, EPF_NONE, PF_DEC, "pid", "the id of the process generating the event."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "exe", "the full name (including the path) of the executable generating the event."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "comm", "the name (excluding thr path) of the executable generating the event."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "args", "the arguments passed on the command line when starting the process generating the event."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "cwd", "the current working directory of the event."},
	{PT_UINT32, EPF_NONE, PF_DEC, "nchilds", "the number of childs of that the process generating the event currently has."},
	{PT_BOOL, EPF_NONE, PF_NA, "ismainthread", "'true' if the thread generating the event is the main one in the process."},
};

sinsp_filter_check_thread::sinsp_filter_check_thread()
{
	m_info.m_name = "thread";
	m_info.m_fields = sinsp_filter_check_thread_fields;
	m_info.m_nfiedls = sizeof(sinsp_filter_check_thread_fields) / sizeof(sinsp_filter_check_thread_fields[0]);
}

int32_t sinsp_filter_check_thread::parse_field_name(const char* str)
{
	string val(str);

	if(string(val, 0, sizeof("arg") - 1) == "arg")
	{
		//
		// 'arg' is handled in a custom way
		//
		throw sinsp_exception("filter error: thread.args filter not implemented yet");
	}
	else
	{
		return sinsp_filter_check::parse_field_name(str);
	}
}

const event_field_info* sinsp_filter_check_thread::get_field_info()
{
	return &sinsp_filter_check_thread_fields[m_field_id];
}

uint8_t* sinsp_filter_check_thread::extract(sinsp_evt *evt)
{
	sinsp_threadinfo* tinfo = evt->get_thread_info();

	if(tinfo == NULL)
	{
		return NULL;
	}

	switch(m_field_id)
	{
	case TYPE_TID:
		return (uint8_t*)&tinfo->m_tid;
	case TYPE_PID:
		return (uint8_t*)&tinfo->m_pid;
	case TYPE_COMM:
		m_tstr = tinfo->get_comm();
		return (uint8_t*)m_tstr.c_str();
	case TYPE_EXE:
		m_tstr = tinfo->get_exe();
		return (uint8_t*)m_tstr.c_str();
	case TYPE_ARGS:
		ASSERT(false);
		throw sinsp_exception("filter error: thread.args filter not implemented yet");
	case TYPE_CWD:
		m_tstr = tinfo->get_cwd();
		return (uint8_t*)m_tstr.c_str();
	case TYPE_ISMAINTHREAD:
		m_tbool = tinfo->is_main_thread();
		return (uint8_t*)&m_tbool;
	default:
		ASSERT(false);
		return NULL;
	}
}

bool sinsp_filter_check_thread::compare(sinsp_evt *evt)
{
	uint8_t* extracted_val = extract(evt);

	if(extracted_val == NULL)
	{
		return false;
	}

	return flt_compare(m_cmpop, 
		sinsp_filter_check_thread_fields[m_field_id].m_type, 
		extracted_val, 
		&m_val_storage);
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_check_event implementation
///////////////////////////////////////////////////////////////////////////////
int32_t sinsp_filter_check_event::parse_field_name(const char* str)
{
/*
	m_type = TYPE_NONE;

	vector<string> components = sinsp_split(val, '.');

	if(components.size() >= 2)
	{
		if(components[1] == "ts")
		{
			m_type = TYPE_TS;
			return;
		}
		else if(components[1] == "name")
		{
			m_type = TYPE_NAME;
			return;
		}
		else if(components[1] == "num")
		{
			m_type = TYPE_NUMBER;
			return;
		}
		else if(components[1] == "cpu")
		{
			m_type = TYPE_CPU;
			return;
		}
		else if(components[1] == "args")
		{
			if(components.size() != 3)
			{
				throw sinsp_exception("filter error: unrecognized argument field " + val);
			}

			m_type = TYPE_ARGS;

			m_argname = components[2];

			return;
		}
	}

	throw sinsp_exception("filter error: unrecognized field " + val);
*/
	return -1;
}

void sinsp_filter_check_event::parse_filter_value(const char* str)
{
/*
	switch(m_type)
	{
	case TYPE_TS:
	case TYPE_NUMBER:
		m_u64val = sinsp_numparser::parseu64(val);
		break;
	case TYPE_CPU:
		m_cpuid = (uint16_t)sinsp_numparser::parseu32(val);
		break;
	case TYPE_NAME:
		if(m_cmpop == CO_CONTAINS)
		{
			m_strval = val;
			m_evttype = PPM_EVENT_MAX;
		}
		else
		{
			try
			{
				m_type = (check_type)sinsp_numparser::parseu32(val);
			}
			catch(...)
			{
				//
				// Search for the event in the table of decoded events
				//
				for(uint32_t j = 0; j < PPM_EVENT_MAX; j++)
				{
					if(val == g_infotables.m_event_info[j].name)
					{
						m_evttype = PPME_MAKE_ENTER(j);
						return;
					}
				}

				//
				// Event not found in the table. It might be an event that we don't support
				// yet, so save it as string and give it a try
				//
				m_strval = val;
				m_evttype = PPM_EVENT_MAX;
			}
		}

		break;
	case TYPE_ARGS:
		{
			try
			{
				if(val[0] == '-')
				{
					m_d64val = sinsp_numparser::parsed64(val);
					m_arg_type = PT_INT64;
					return;
				}
				else
				{
					m_u64val = sinsp_numparser::parseu64(val);
					m_arg_type = PT_UINT64;
					return;
				}
			}
			catch(...)
			{
			}

			m_strval = val;
			m_arg_type = PT_CHARBUF;
		}
		break;
	default:
		ASSERT(false);
	}
*/
}

const event_field_info* sinsp_filter_check_event::get_field_info()
{
	return NULL;
}

uint8_t* sinsp_filter_check_event::extract(sinsp_evt *evt)
{
	ASSERT(false);
	return NULL;
}

bool sinsp_filter_check_event::compare(sinsp_evt *evt)
{
	sinsp_threadinfo* tinfo = evt->get_thread_info();

	if(tinfo == NULL)
	{
		return false;
	}

	switch(m_type)
	{
	case TYPE_TS:
		if(flt_compare(m_cmpop, PT_UINT64, &evt->m_pevt->ts, &m_u64val) == true)
		{
			return true;
		}
		break;
	case TYPE_NAME:
		{
			uint16_t enter_type;
			char* evname;

			if(evt->m_pevt->type == PPME_GENERIC_E || evt->m_pevt->type == PPME_GENERIC_X)
			{
				sinsp_evt_param *parinfo = evt->get_param(0);
				ASSERT(parinfo->m_len == sizeof(uint16_t));
				uint16_t evid = *(uint16_t *)parinfo->m_val;

				evname = g_infotables.m_syscall_info_table[evid].name;
				enter_type = PPM_EVENT_MAX;
			}
			else
			{
				evname = (char*)evt->get_name();
				enter_type = PPME_MAKE_ENTER(evt->m_pevt->type);
			}

			if(m_evttype == PPM_EVENT_MAX)
			{
				if(flt_compare(m_cmpop, PT_CHARBUF, 
					evname, (char*)m_strval.c_str()) == true)
				{
					return true;
				}
			}
			else
			{
				if(flt_compare(m_cmpop, PT_UINT16, 
					&enter_type, &m_evttype) == true)
				{
					return true;
				}
			}
		}
		break;
	case TYPE_NUMBER:
		if(flt_compare(m_cmpop, PT_UINT64, &evt->m_evtnum, &m_u64val) == true)
		{
			return true;
		}
		break;
	case TYPE_CPU:
		{
			int16_t cpuid = evt->get_cpuid();

			if(flt_compare(m_cmpop, PT_UINT64, &cpuid, &m_u64val) == true)
			{
				return true;
			}
		}
		break;
	case TYPE_ARGS:
		{
			const char* resolved_argstr;
			const char* argstr = evt->get_param_value_str(m_argname.c_str(), 
				&resolved_argstr);

			switch(m_arg_type)
			{
			case PT_CHARBUF:
				if(argstr && flt_compare(m_cmpop, PT_CHARBUF, (void*)argstr, (void*)m_strval.c_str()) == true)
				{
					return true;
				}

				break;
			case PT_UINT64:
				{
					uint64_t dval;
					if(resolved_argstr && !sinsp_numparser::tryparseu64(resolved_argstr, &dval))
					{
						if(argstr && !sinsp_numparser::tryparseu64(argstr, &dval))
						{
							throw sinsp_exception("filter error: field " + m_argname + " is not a number");
						}
					}

					if(flt_compare(m_cmpop, PT_INT64, &dval, &m_u64val) == true)
					{
						return true;
					}
				}
				break;
			case PT_INT64:
				{
					int64_t dval;
					if(resolved_argstr && !sinsp_numparser::tryparsed64(resolved_argstr, &dval))
					{
						if(argstr && !sinsp_numparser::tryparsed64(argstr, &dval))
						{
							throw sinsp_exception("filter error: field " + m_argname + " is not a number");
						}
					}

					if(flt_compare(m_cmpop, PT_INT64, &dval, &m_d64val) == true)
					{
						return true;
					}
				}
				break;
			default:
				ASSERT(false);
				break;
			}
		}
		break;
	default:
		ASSERT(false);
		break;
	}

	return false;
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_check_user implementation
///////////////////////////////////////////////////////////////////////////////
int32_t sinsp_filter_check_user::parse_field_name(const char* str)
{
/*
	m_type = TYPE_NONE;

	vector<string> components = sinsp_split(val, '.');

	if(components.size() == 2)
	{
		if(components[1] == "uid")
		{
			m_type = TYPE_UID;
			return;
		}
		else if(components[1] == "name")
		{
			m_type = TYPE_NAME;
			return;
		}
		else if(components[1] == "homedir")
		{
			m_type = TYPE_HOMEDIR;
			return;
		}
		else if(components[1] == "shell")
		{
			m_type = TYPE_SHELL;
			return;
		}
	}

	throw sinsp_exception("filter error: unrecognized field " + val);
*/
	return -1;
}

void sinsp_filter_check_user::parse_filter_value(const char* str)
{
/*
	switch(m_type)
	{
	case TYPE_UID:
		m_uid = sinsp_numparser::parsed32(val);
		break;
	case TYPE_NAME:
	case TYPE_HOMEDIR:
	case TYPE_SHELL:
		m_strval = val;
		break;
	default:
		ASSERT(false);
	}
*/
}

const event_field_info* sinsp_filter_check_user::get_field_info()
{
	return NULL;
}

uint8_t* sinsp_filter_check_user::extract(sinsp_evt *evt)
{
	ASSERT(false);
	return NULL;
}

bool sinsp_filter_check_user::compare(sinsp_evt *evt)
{
	sinsp_threadinfo* tinfo = evt->get_thread_info();
	scap_userinfo* uinfo;

	if(tinfo == NULL)
	{
		return false;
	}

	if(m_type != TYPE_UID)
	{
		unordered_map<uint32_t, scap_userinfo*>::iterator it;

		ASSERT(m_inspector != NULL);
		unordered_map<uint32_t, scap_userinfo*>* userlist = 
			(unordered_map<uint32_t, scap_userinfo*>*)m_inspector->get_userlist();
		ASSERT(userlist->size() != 0);

		it = userlist->find(tinfo->m_uid);
		if(it == userlist->end())
		{
			ASSERT(false);
			return false;
		}

		uinfo = it->second;
		ASSERT(uinfo != NULL);
	}

	switch(m_type)
	{
	case TYPE_UID:
		if(flt_compare(m_cmpop, PT_PID, &tinfo->m_uid, &m_uid) == true)
		{
			return true;
		}
		break;
	case TYPE_NAME:
		if(flt_compare(m_cmpop, PT_CHARBUF, uinfo->name, (char*)m_strval.c_str()) == true)
		{
			return true;
		}
		break;
	case TYPE_HOMEDIR:
		if(flt_compare(m_cmpop, PT_CHARBUF, uinfo->homedir, (char*)m_strval.c_str()) == true)
		{
			return true;
		}
		break;
	case TYPE_SHELL:
		if(flt_compare(m_cmpop, PT_CHARBUF, uinfo->shell, (char*)m_strval.c_str()) == true)
		{
			return true;
		}
		break;
	default:
		ASSERT(false);
		break;
	}

	return false;
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_check_group implementation
///////////////////////////////////////////////////////////////////////////////
int32_t sinsp_filter_check_group::parse_field_name(const char* str)
{
/*
	m_type = TYPE_NONE;

	vector<string> components = sinsp_split(val, '.');

	if(components.size() == 2)
	{
		if(components[1] == "gid")
		{
			m_type = TYPE_GID;
			return;
		}
		else if(components[1] == "name")
		{
			m_type = TYPE_NAME;
			return;
		}
	}

	throw sinsp_exception("filter error: unrecognized field " + val);
*/
	return -1;
}

void sinsp_filter_check_group::parse_filter_value(const char* str)
{
/*
	switch(m_type)
	{
	case TYPE_GID:
		m_gid = sinsp_numparser::parsed32(val);
		break;
	case TYPE_NAME:
		m_name = val;
		break;
	default:
		ASSERT(false);
	}
*/
}

const event_field_info* sinsp_filter_check_group::get_field_info()
{
	return NULL;
}

uint8_t* sinsp_filter_check_group::extract(sinsp_evt *evt)
{
	ASSERT(false);
	return NULL;
}

bool sinsp_filter_check_group::compare(sinsp_evt *evt)
{
	sinsp_threadinfo* tinfo = evt->get_thread_info();

	if(tinfo == NULL)
	{
		return false;
	}

	switch(m_type)
	{
	case TYPE_GID:
		if(flt_compare(m_cmpop, PT_PID, &tinfo->m_gid, &m_gid) == true)
		{
			return true;
		}
		break;
	case TYPE_NAME:
		{
			unordered_map<uint32_t, scap_groupinfo*>::iterator it;

			ASSERT(m_inspector != NULL);
			unordered_map<uint32_t, scap_groupinfo*>* grouplist = 
				(unordered_map<uint32_t, scap_groupinfo*>*)m_inspector->get_grouplist();
			ASSERT(grouplist->size() != 0);

			it = grouplist->find(tinfo->m_gid);
			if(it == grouplist->end())
			{
				ASSERT(false);
				return false;
			}

			scap_groupinfo* ginfo = it->second;
			ASSERT(ginfo != NULL);

			if(flt_compare(m_cmpop, PT_CHARBUF, ginfo->name, (char*)m_name.c_str()) == true)
			{
				return true;
			}
		}
		break;
	default:
		ASSERT(false);
		break;
	}

	return false;
}

///////////////////////////////////////////////////////////////////////////////
// rawstring_check implementation
///////////////////////////////////////////////////////////////////////////////
const event_field_info rawstring_check_fields[] =
{
	{PT_CHARBUF, EPF_NONE, PF_NA, "NA", "INTERNAL."},
};

rawstring_check::rawstring_check(string text)
{
	m_field = rawstring_check_fields;
	set_text(text);
}

void rawstring_check::set_text(string text)
{
	m_text = text;
}

int32_t rawstring_check::parse_field_name(const char* str)
{
	ASSERT(false);
	return -1;
}

void rawstring_check::parse_filter_value(const char* str)
{
	ASSERT(false);
}

const event_field_info* rawstring_check::get_field_info()
{
	return &rawstring_check_fields[0];
}

uint8_t* rawstring_check::extract(sinsp_evt *evt)
{
	return (uint8_t*)m_text.c_str();
}

bool rawstring_check::compare(sinsp_evt *evt)
{
	//
	// This should never be used by the filtering engine, only by the event formatter
	//
	ASSERT(false);
	return false;
}

#endif // HAS_FILTERING
