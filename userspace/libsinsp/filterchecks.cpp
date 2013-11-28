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
	{PT_INT64, EPF_NONE, PF_DEC, "fd.num", "the unique number identifying the file descriptor."},
	{PT_UINT32, EPF_NONE, PF_DEC, "fd.type", "type of FD. Can be 'file', 'ipv4', 'ipv6', 'unix', 'pipe', 'event', 'signalfd', 'eventpoll', 'inotify' or 'signalfd."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "fd.name", "FD full name. If the fd is a file, this field contains the full path. If the FD is a socket, this field contain the connection tuple."},
	{PT_SOCKADDR, EPF_FILTER_ONLY, PF_NA, "fd.ip", "matches the ip address (client or server) of the fd."},
	{PT_SOCKADDR, EPF_NONE, PF_NA, "fd.cip", "client IP address."},
	{PT_SOCKADDR, EPF_NONE, PF_NA, "fd.sip", "server IP address."},
	{PT_UINT64, EPF_FILTER_ONLY, PF_DEC, "fd.port", "matches the port (client or server) of the fd."},
	{PT_PORT, EPF_NONE, PF_DEC, "fd.cport", "client TCP/UDP port."},
	{PT_PORT, EPF_NONE, PF_DEC, "fd.sport", "server TCP/UDP port."},
	{PT_UINT8, EPF_NONE, PF_DEC, "fd.l4proto", "IP protocol number."},
	{PT_SOCKFAMILY, EPF_NONE, PF_DEC, "fd.sockfamily", "the socket family for socket events. Can be 'ip' or 'unix'."},
};

sinsp_filter_check_fd::sinsp_filter_check_fd()
{
	m_info.m_name = "fd";
	m_info.m_fields = sinsp_filter_check_fd_fields;
	m_info.m_nfiedls = sizeof(sinsp_filter_check_fd_fields) / sizeof(sinsp_filter_check_fd_fields[0]);
}

int32_t sinsp_filter_check_fd::parse_field_name(const char* str)
{
	return sinsp_filter_check::parse_field_name(str);
}

uint8_t* sinsp_filter_check_fd::extract_fdtype(sinsp_fdinfo* fdinfo)
{
	switch(fdinfo->m_type)
	{
	case SCAP_FD_FILE:
	case SCAP_FD_DIRECTORY:
		return (uint8_t*)"file";
	case SCAP_FD_IPV4_SOCK:
	case SCAP_FD_IPV4_SERVSOCK:
		return (uint8_t*)"ipv4";
	case SCAP_FD_IPV6_SOCK:
	case SCAP_FD_IPV6_SERVSOCK:
		return (uint8_t*)"ipv6";
	case SCAP_FD_UNIX_SOCK:
		return (uint8_t*)"unix";
	case SCAP_FD_FIFO:
		return (uint8_t*)"pipe";
	case SCAP_FD_EVENT:
		return (uint8_t*)"event";
	case SCAP_FD_SIGNALFD:
		return (uint8_t*)"signalfd";
	case SCAP_FD_EVENTPOLL:
		return (uint8_t*)"eventpoll";
	case SCAP_FD_INOTIFY:
		return (uint8_t*)"inotify";
	case SCAP_FD_TIMERFD:
		return (uint8_t*)"timerfd";
	default:
		ASSERT(false);
		return NULL;
	}
}

uint8_t* sinsp_filter_check_fd::extract(sinsp_evt *evt)
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
			return NULL;
		}

		fdinfo = evt->get_fd_info();

		if(fdinfo == NULL && tinfo->m_lastevent_fd != -1)
		{
			fdinfo = tinfo->get_fd(tinfo->m_lastevent_fd);
		}

		// We'll check if fd is null below
	}
	else
	{
		return false;
	}

	//
	// TYPE_FDNUM doesn't need fdinfo
	//
	if(m_field_id == TYPE_FDNUM)
	{
		return (uint8_t*)&tinfo->m_lastevent_fd;
	}

	if(fdinfo == NULL)
	{
		ASSERT(false);
		return NULL;
	}

	switch(m_field_id)
	{
	case TYPE_FDNAME:
		if(fdinfo != NULL)
		{
			return (uint8_t*)fdinfo->m_name.c_str();
		}
		else
		{
			return NULL;
		}

		break;
	case TYPE_FDTYPE:
		if(fdinfo != NULL)
		{
			return extract_fdtype(fdinfo);
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
					return NULL;
				}
			}
			else if(evt_type == SCAP_FD_IPV4_SERVSOCK)
			{
				if(fdinfo->m_info.m_ipv4serverinfo.m_ip == m_ip)
				{
					return NULL;
				}
			}
		}

		break;
	case TYPE_CLIENTIP:
		{
			scap_fd_type evt_type = fdinfo->m_type;

			if(evt_type == SCAP_FD_IPV4_SOCK)
			{
				return (uint8_t*)&(fdinfo->m_info.m_ipv4info.m_fields.m_sip);
			}
		}

		break;
	case TYPE_SERVERIP:
		if(fdinfo != NULL)
		{
			scap_fd_type evt_type = fdinfo->m_type;

			if(evt_type == SCAP_FD_IPV4_SOCK)
			{
				return (uint8_t*)&(fdinfo->m_info.m_ipv4info.m_fields.m_dip);
			}
			else if(evt_type == SCAP_FD_IPV4_SERVSOCK)
			{
				return (uint8_t*)&(fdinfo->m_info.m_ipv4serverinfo.m_ip);
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
					return NULL;
				}
			}
			else if(evt_type == SCAP_FD_IPV4_SERVSOCK)
			{
				if(fdinfo->m_info.m_ipv4serverinfo.m_port == m_port)
				{
					return NULL;
				}
			}
			else if(evt_type == SCAP_FD_IPV6_SOCK)
			{
				if(fdinfo->m_info.m_ipv6info.m_fields.m_sport == m_port ||
					fdinfo->m_info.m_ipv6info.m_fields.m_dport == m_port)
				{
					return NULL;
				}
			}
			else if(evt_type == SCAP_FD_IPV6_SERVSOCK)
			{
				if(fdinfo->m_info.m_ipv6serverinfo.m_port == m_port)
				{
					return NULL;
				}
			}
		}
	case TYPE_CLIENTPORT:
		if(fdinfo != NULL)
		{
			scap_fd_type evt_type = fdinfo->m_type;

			if(evt_type == SCAP_FD_IPV4_SOCK)
			{
				return (uint8_t*)&(fdinfo->m_info.m_ipv4info.m_fields.m_sport);
			}
			else if(evt_type == SCAP_FD_IPV6_SOCK)
			{
				return (uint8_t*)&(fdinfo->m_info.m_ipv6info.m_fields.m_sport);
			}
		}
	case TYPE_SERVERPORT:
		if(fdinfo != NULL)
		{
			scap_fd_type evt_type = fdinfo->m_type;

			if(evt_type == SCAP_FD_IPV4_SOCK)
			{
				return (uint8_t*)&(fdinfo->m_info.m_ipv4info.m_fields.m_dport);
			}
			else if(evt_type == SCAP_FD_IPV4_SERVSOCK)
			{
				return (uint8_t*)&(fdinfo->m_info.m_ipv4serverinfo.m_port);
			}
			else if(evt_type == SCAP_FD_IPV6_SOCK)
			{
				return (uint8_t*)&(fdinfo->m_info.m_ipv6info.m_fields.m_dport);
			}
			else if(evt_type == SCAP_FD_IPV6_SERVSOCK)
			{
				return (uint8_t*)&(fdinfo->m_info.m_ipv6serverinfo.m_port);
			}
		}

		break;

	default:
		ASSERT(false);
	}

	return false;
}

bool sinsp_filter_check_fd::compare(sinsp_evt *evt)
{
	uint8_t* extracted_val = extract(evt);

	if(extracted_val == NULL)
	{
		return false;
	}

	return flt_compare(m_cmpop, 
		m_info.m_fields[m_field_id].m_type, 
		extracted_val, 
		&m_val_storage);
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
		m_tbool = (uint32_t)tinfo->is_main_thread();
		return (uint8_t*)&m_tbool;
	default:
		ASSERT(false);
		return NULL;
	}
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

uint8_t* sinsp_filter_check_event::extract(sinsp_evt *evt)
{
	ASSERT(false);
	return NULL;
}

/*
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
*/

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

uint8_t* sinsp_filter_check_user::extract(sinsp_evt *evt)
{
	ASSERT(false);
	return NULL;
}

/*
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
*/

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

uint8_t* sinsp_filter_check_group::extract(sinsp_evt *evt)
{
	ASSERT(false);
	return NULL;
}

/*
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
*/

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

uint8_t* rawstring_check::extract(sinsp_evt *evt)
{
	return (uint8_t*)m_text.c_str();
}

/*
bool rawstring_check::compare(sinsp_evt *evt)
{
	//
	// This should never be used by the filtering engine, only by the event formatter
	//
	ASSERT(false);
	return false;
}
*/

#endif // HAS_FILTERING
