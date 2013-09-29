//
// Why isn't this parser written using antlr or some other parser generator?
// Essentially, after dealing with that stuff multiple times in the past, and fighting for a day
// to configure everything with crappy documentation and code that doesn't compile,
// I decided that I agree with this http://mortoray.com/2012/07/20/why-i-dont-use-a-parser-generator/
// and that I'm going with a manually written parser. The grammar is simple enough that it's not
// going to take more time. On the other hand I will avoid a crappy dependency that breaks my 
// code at every new release, and I will have a cleaner and easier to understand code base.
//

#include "sinsp.h"
#include "sinsp_int.h"

#ifdef HAS_FILTERING
#include "filter.h"

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_check implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_filter_check::sinsp_filter_check()
{
	m_boolop = BO_NONE;
	m_cmpop = CO_NONE;
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_check_comm implementation
///////////////////////////////////////////////////////////////////////////////
bool sinsp_filter_check_comm::recognize_operand(string operand)
{
	if(operand == "comm")
	{
		return true;
	}
	else
	{
		return false;
	}
}

void sinsp_filter_check_comm::parse_operand2(string val)
{
	m_comm = val;
}

bool sinsp_filter_check_comm::run(sinsp_evt *evt)
{
	ASSERT(evt);

	sinsp_threadinfo* tinfo = evt->get_thread_info();

	if(tinfo != NULL && sinsp_evt::compare(m_cmpop, 
		PT_CHARBUF, 
		(void*)tinfo->get_comm().c_str(), 
		(void*)m_comm.c_str()) == true)
	{
		return true;
	}
	else
	{
		return false;
	}
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_check_tid implementation
///////////////////////////////////////////////////////////////////////////////
bool sinsp_filter_check_tid::recognize_operand(string operand)
{
	if(operand == "tid")
	{
		return true;
	}
	else
	{
		return false;
	}
}

void sinsp_filter_check_tid::parse_operand2(string val)
{
	m_tid = sins_numparser::parse(val);
}

bool sinsp_filter_check_tid::run(sinsp_evt *evt)
{
	ASSERT(evt);

	sinsp_threadinfo* tinfo = evt->get_thread_info();

	if(tinfo != NULL && sinsp_evt::compare(m_cmpop, PT_PID, &tinfo->m_tid, &m_tid) == true)
	{
		return true;
	}
	else
	{
		return false;
	}
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_check_fd implementation
///////////////////////////////////////////////////////////////////////////////
bool sinsp_filter_check_fd::recognize_operand(string operand)
{
	if(operand.substr(0, string("fd").length()) == "fd")
	{
		return true;
	}
	else
	{
		return false;
	}
}

void sinsp_filter_check_fd::parse_operand1(string val)
{
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
			else if(components[1] == "port")
			{
				m_type = TYPE_PORT;
				return;
			}
		}
	}

	throw sinsp_exception("filter error: unrecognized field " + val);
}

void sinsp_filter_check_fd::parse_operand2(string val)
{
	switch(m_type)
	{
	case TYPE_FDNUM:
		m_fd = sins_numparser::parse(val);
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
		else if(val == "sock")
		{
			m_fd_type = FDT_SOCK;
			return;
		}
		else if(val == "ipv4sock")
		{
			m_fd_type = FDT_IPV4_SOCK;
			return;
		}
		else if(val == "ipv6sock")
		{
			m_fd_type = FDT_IPV6_SOCK;
			return;
		}
		else if(val == "unixsock")
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
			throw sinsp_exception("unsupported fd type " + val);
		}
		break;
	case TYPE_IP:
		{
			if(inet_pton(AF_INET, val.c_str(), &m_ip) != 1)
			{
				throw sinsp_exception("malformed IP address " + val);
			}
		}
		break;
	case TYPE_PORT:
		m_port = sins_numparser::parse(val);
		break;
	default:
		ASSERT(false);
	}
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

bool sinsp_filter_check_fd::run(sinsp_evt *evt)
{
	sinsp_threadinfo* tinfo;
	sinsp_fdinfo* fdinfo;
	ppm_event_flags eflags = evt->get_flags();
	ASSERT(evt);

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

		fdinfo = tinfo->get_fd(tinfo->m_lastevent_fd);
	}
	else
	{
		return false;
	}

	switch(m_type)
	{
	case TYPE_FDNUM:
		if(sinsp_evt::compare(m_cmpop, PT_PID, &tinfo->m_lastevent_fd, &m_fd) == true)
		{
			return true;
		}

		break;
	case TYPE_FDNAME:
		if(fdinfo != NULL && sinsp_evt::compare(m_cmpop, 
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

		break;

	default:
		ASSERT(false);
	}

	return false;
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_expression implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_filter_expression::sinsp_filter_expression()
{
	m_parent = NULL;
}

sinsp_filter_expression::~sinsp_filter_expression()
{
	uint32_t j;

	for(j = 0; j < m_checks.size(); j++)
	{
		delete m_checks[j];
	}
}

void sinsp_filter_expression::add_check(sinsp_filter_check* chk)
{
	m_checks.push_back(chk);
}

void sinsp_filter_expression::parse(string expr)
{
}
	
bool sinsp_filter_expression::run(sinsp_evt *evt)
{
	uint32_t j;
	uint32_t size = m_checks.size();
	bool res = true;
	bool chkres;
	 
	for(j = 0; j < size; j++)
	{
		sinsp_filter_check* chk = m_checks[j];
		ASSERT(chk != NULL);

		chkres = chk->run(evt);
		if(j == 0)
		{
			switch(chk->m_boolop)
			{
			case BO_NONE:
				res = chkres;
				break;
			case BO_NOT:
				res = !chkres;
				break;
			default:
				ASSERT(false);
				break;
			}
		}
		else
		{
			switch(chk->m_boolop)
			{
			case BO_OR:
				res = res || chkres;
				break;
			case BO_AND:
				res = res && chkres;
				break;
			case BO_ORNOT:
				res = res || !chkres;
				break;
			case BO_ANDNOT:
				res = res && !chkres;
				break;
			default:
				ASSERT(false);
				break;
			}
		}
	}

	return res;
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_filter::sinsp_filter(string fltstr)
{
//fltstr = "(comm ruby and tid 8976) or (comm rsyslogd and tid 393)";
//fltstr = "(tid=63458)";
//fltstr = "(tid!=0)";
//fltstr = "fd.ip = 192.168.171.196 and fd.port = 53";

	m_scanpos = -1;
	m_scansize = 0;
	m_state = ST_NEED_EXPRESSION;
	m_curexpr = &m_filter;
	m_last_boolop = BO_NONE;
	m_nest_level = 0;

	parse(fltstr);
}

bool sinsp_filter::isblank(char c)
{
	if(c == ' ' || c == '\t' || c == '\n' || c == '\r')
	{
		return true;
	}
	else
	{
		return false;
	}
}

bool sinsp_filter::is_special_char(char c)
{
	if(c == '(' || c == ')' || c == '!' || c == '=' || c == '<' || c == '>')
	{
		return true;
	}

	return false;
}

char sinsp_filter::next()
{
	while(true)
	{
		m_scanpos++;

		if(m_scanpos >= m_scansize)
		{
			return 0;
		}

		if(!isblank(m_fltstr[m_scanpos]))
		{
			return m_fltstr[m_scanpos];
		}
	}
}

string sinsp_filter::next_operand()
{
	int32_t start;

	//
	// Skip spaces
	//
	if(isblank(m_fltstr[m_scanpos]))
	{
		next();
	}

	//
	// Mark the beginning of the word
	//
	start = m_scanpos;

	for(; m_scanpos < m_scansize; m_scanpos++)
	{
		char curchar = m_fltstr[m_scanpos];

		if(isblank(curchar) || is_special_char(curchar))
		{
			//
			// End of word
			//
			ASSERT(m_scanpos > start);
			string res = m_fltstr.substr(start, m_scanpos - start);

			if(curchar == '(' || curchar == ')')
			{
				m_scanpos--;
			}

			return res;
		}
	}

	//
	// End of filter
	//
	return m_fltstr.substr(start, m_scansize - 1);
}

bool sinsp_filter::compare_no_consume(string str)
{
	if(m_scanpos + (int32_t)str.size() >= m_scansize)
	{
		throw sinsp_exception("filter error: truncated filter");
	}

	string tstr = m_fltstr.substr(m_scanpos, str.size());

	if(tstr == str)
	{
		return true;
	}
	else
	{
		return false;
	}
}

ppm_cmp_operator sinsp_filter::next_comparison_operator()
{
	int32_t start;

	//
	// Skip spaces
	//
	if(isblank(m_fltstr[m_scanpos]))
	{
		next();
	}

	//
	// Mark the beginning of the word
	//
	start = m_scanpos;

	if(compare_no_consume("="))
	{
		m_scanpos += 1;
		return CO_EQ;
	}
	if(compare_no_consume("!="))
	{
		m_scanpos += 2;
		return CO_NE;
	}
	if(compare_no_consume("contains"))
	{
		m_scanpos += 8;
		return CO_CONTAINS;
	}
	else
	{
		throw sinsp_exception("filter error: unrecognized comparison operator after " + m_fltstr.substr(0, start));
	}
}

void sinsp_filter::parse_check(sinsp_filter_expression* parent_expr, boolop op)
{
	uint32_t startpos = m_scanpos;
	string operand1 = next_operand();
	sinsp_filter_check* chk;

	//////////////////////////////////////////////////////////////////////////////
	// ADD NEW FILTER CHECK CLASSES HERE
	//////////////////////////////////////////////////////////////////////////////
	if(sinsp_filter_check_comm::recognize_operand(operand1))
	{
		sinsp_filter_check_comm* chk_comm = new sinsp_filter_check_comm();
		chk = (sinsp_filter_check*)chk_comm;
	}
	else if(sinsp_filter_check_tid::recognize_operand(operand1))
	{
		sinsp_filter_check_tid* chk_tid = new sinsp_filter_check_tid();
		chk = (sinsp_filter_check*)chk_tid;
	}
	else if(sinsp_filter_check_fd::recognize_operand(operand1))
	{
		sinsp_filter_check_fd* chk_fd = new sinsp_filter_check_fd();
		chk = (sinsp_filter_check*)chk_fd;
	}
	else
	{
		throw sinsp_exception("filter error: unrecognized operand " + operand1 + " at pos " + to_string(startpos));
	}
	//////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////

	ppm_cmp_operator co = next_comparison_operator();
	string operand2 = next_operand();

	chk->parse_operand1(operand1);
	chk->parse_operand2(operand2);
	chk->m_boolop = op;
	chk->m_cmpop = co;

	parent_expr->add_check(chk);
}

void sinsp_filter::push_expression(boolop op)
{
	sinsp_filter_expression* newexpr = new sinsp_filter_expression();
	newexpr->m_boolop = op;
	newexpr->m_parent = m_curexpr;
	m_last_boolop = BO_NONE;

	m_curexpr->m_checks.push_back((sinsp_filter_check*)newexpr);
	m_curexpr = newexpr;
	m_nest_level++;
}

void sinsp_filter::pop_expression()
{
	ASSERT(m_curexpr->m_parent != NULL);

	m_curexpr = m_curexpr->m_parent;
	m_nest_level--;
}

void sinsp_filter::parse(string fltstr)
{
	m_fltstr = fltstr;
	m_scansize = m_fltstr.size();

	while(true)
	{
		char a = next();

		switch(a)
		{
		case 0:
			//
			// Finished parsing the filter string
			//
			if(m_nest_level != 0)
			{
				throw sinsp_exception("filter error: unexpected end of filter");
			}

			if(m_state != ST_EXPRESSION_DONE)
			{
				throw sinsp_exception("filter error: unexpected end of filter at position " + to_string(m_scanpos));
			}

			//
			// Good filter
			//
			return;

			break;
		case '(':
			if(m_state != ST_NEED_EXPRESSION)
			{
				throw sinsp_exception("unexpected '(' after " + m_fltstr.substr(0, m_scanpos));
			}

			push_expression(m_last_boolop);

			break;
		case ')':
			pop_expression();
			break;
		case 'o':
			if(next() == 'r')
			{
				m_last_boolop = BO_OR;
			}
			else
			{
				throw sinsp_exception("syntax error in filter at position " + to_string(m_scanpos));
			}

			if(m_state != ST_EXPRESSION_DONE)
			{
				throw sinsp_exception("unexpected 'or' after " + m_fltstr.substr(0, m_scanpos));
			}

			m_state = ST_NEED_EXPRESSION;

			break;
		case 'a':
			if(next() == 'n' && next() == 'd')
			{
				m_last_boolop = BO_AND;
			}
			else
			{
				throw sinsp_exception("syntax error in filter at position " + to_string(m_scanpos));
			}

			if(m_state != ST_EXPRESSION_DONE)
			{
				throw sinsp_exception("unexpected 'and' after " + m_fltstr.substr(0, m_scanpos));
			}

			m_state = ST_NEED_EXPRESSION;

			break;
		case 'n':
			if(next() == 'o' && next() == 't')
			{
				m_last_boolop = (boolop)((uint32_t)m_last_boolop | BO_NOT);
			}
			else
			{
				throw sinsp_exception("syntax error in filter at position " + to_string(m_scanpos));
			}

			if(m_state != ST_EXPRESSION_DONE)
			{
				throw sinsp_exception("unexpected 'not' after " + m_fltstr.substr(0, m_scanpos));
			}

			m_state = ST_NEED_EXPRESSION;

			break;
		default:
			parse_check(m_curexpr, m_last_boolop);

			m_state = ST_EXPRESSION_DONE;

			break;
		}
	}

	vector<string> components = sinsp_split(m_fltstr, ' ');
}

bool sinsp_filter::run(sinsp_evt *evt)
{
	return m_filter.run(evt);
}

#endif // HAS_FILTERING
