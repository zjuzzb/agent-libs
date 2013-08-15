#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif // _WIN32

#include "../../driver/ppm_ringbuffer.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "parsers.h"
#include "connectinfo.h"
#include "analyzer.h"
#include "utils.h"
#include "sinsp_errno.h"

sinsp_parser::sinsp_parser(sinsp *inspector) :
	m_tmp_evt(m_inspector)
{
	m_inspector = inspector;
}

sinsp_parser::~sinsp_parser()
{
}

///////////////////////////////////////////////////////////////////////////////
// PROCESSING ENTRY POINT
///////////////////////////////////////////////////////////////////////////////
void sinsp_parser::process_event(sinsp_evt *evt)
{
/*
if(evt->get_num() == 3307)
{
	int a = 0;
}
*/
	//
	// Cleanup the event-related state
	//
	reset(evt);

	//
	// Route the event to the proper function
	//
	uint16_t etype = evt->get_type();

	switch(etype)
	{
	case PPME_SOCKET_SENDTO_E:
	case PPME_SYSCALL_WRITEV_E:
	case PPME_SYSCALL_PWRITE_E:
	case PPME_SYSCALL_PWRITEV_E:
	case PPME_SYSCALL_OPEN_E:
	case PPME_SOCKET_SOCKET_E:
	case PPME_SYSCALL_EVENTFD_E:
	case PPME_SYSCALL_CHDIR_E:
	case PPME_SYSCALL_FCHDIR_E:
	case PPME_SYSCALL_CREAT_E:
	case PPME_SYSCALL_OPENAT_E:
	case PPME_SOCKET_SHUTDOWN_E:
		store_event(evt);
		break;
	case PPME_CLONE_X:
		parse_clone_exit(evt); // does memory allocation
		break;
	case PPME_SYSCALL_EXECVE_X:
		parse_execve_exit(evt); // does memory allocation
		break;
	case PPME_PROCEXIT_E:
		parse_thread_exit(evt);
		break;
	case PPME_SYSCALL_OPEN_X:
	case PPME_SYSCALL_CREAT_X:
	case PPME_SYSCALL_OPENAT_X:
		parse_open_openat_creat_exit(evt);  // does memory allocation
		break;
	case PPME_SYSCALL_PIPE_X:
		parse_pipe_exit(evt);    // does memory allocation
		break;
	case PPME_SOCKET_SOCKETPAIR_X:
		parse_socketpair_exit(evt);
		break;
	case PPME_SOCKET_SOCKET_X:
		parse_socket_exit(evt); // does memory allocation
		break;
	case PPME_SOCKET_BIND_X:
		parse_bind_exit(evt);
		break;
	case PPME_SOCKET_CONNECT_X:
		parse_connect_exit(evt);
		break;
	case PPME_SOCKET_ACCEPT_X:
	case PPME_SOCKET_ACCEPT4_X:
		parse_accept_exit(evt, true);
		break;
	case PPME_SYSCALL_CLOSE_E:
		parse_close_enter(evt);
		break;
	case PPME_SYSCALL_CLOSE_X:
		parse_close_exit(evt);
		break;
	case PPME_SYSCALL_READ_X:
	case PPME_SYSCALL_WRITE_X:
	case PPME_SOCKET_RECV_X:
	case PPME_SOCKET_SEND_X:
	case PPME_SOCKET_RECVFROM_X:
	case PPME_SOCKET_SENDTO_X:
	case PPME_SYSCALL_READV_X:
	case PPME_SYSCALL_WRITEV_X:
	case PPME_SYSCALL_PREAD_X:
	case PPME_SYSCALL_PWRITE_X:
	case PPME_SYSCALL_PREADV_X:
	case PPME_SYSCALL_PWRITEV_X:
		parse_rw_exit(evt);
		break;
	case PPME_SYSCALL_FSTAT_X:
	case PPME_SYSCALL_FSTAT64_X:
		parse_fstat_exit(evt);
		break;
	case PPME_SYSCALL_EVENTFD_X :
		parse_eventfd_exit(evt);
		break;
	case PPME_SYSCALL_CHDIR_X:
		parse_chdir_exit(evt);
		break;
	case PPME_SYSCALL_FCHDIR_X:
		parse_fchdir_exit(evt);
		break;
	case PPME_SYSCALL_GETCWD_X:
		parse_getcwd_exit(evt);
		break;
	case PPME_SOCKET_SHUTDOWN_X:
		parse_shutdown_exit(evt);
		break;
	case PPME_SYSCALL_DUP_X:
		parse_dup_exit(evt);
		break;
	case PPME_SYSCALL_SIGNALFD_X:
		parse_signalfd_exit(evt);
		break;
	case PPME_SYSCALL_TIMERFD_CREATE_X:
		parse_timerfd_create_exit(evt);
		break;
	case PPME_SYSCALL_INOTIFY_INIT_X:
		parse_inotify_init_exit(evt);
		break;
	default:
		break;
	}
}

///////////////////////////////////////////////////////////////////////////////
// HELPERS
///////////////////////////////////////////////////////////////////////////////

//
// Called before starting the parsing.
// Returns false in case of issues resetting the state.
//
bool sinsp_parser::reset(sinsp_evt *evt)
{
	//
	// Before anything can happen, the event needs to be initialized
	//
	evt->init();

	ppm_event_flags eflags = evt->get_flags();
	uint16_t etype = evt->get_type();

	evt->m_fdinfo = NULL;

	//
	// Extract the process
	//

	//
	// If we're exiting a clone, we don't look for /proc
	//
	bool query_os;
	if(etype == PPME_CLONE_X)
	{
		query_os = false;
	}
	else
	{
		query_os = true;
	}

	evt->m_tinfo = evt->get_thread_info(query_os);
	if(!evt->m_tinfo)
	{
		if(evt->get_type() == PPME_CLONE_X)
		{
#ifdef GATHER_INTERNAL_STATS
			m_inspector->m_thread_manager->m_failed_lookups->decrement();
#endif
		}
		else
		{
			ASSERT(false);
		}

		return false;
	}

	if(PPME_IS_ENTER(etype))
	{
		evt->m_tinfo->m_lastevent_type = etype;

		if(eflags & EC_USES_FD)
		{
			sinsp_evt_param *parinfo;

			//
			// Get the fd.
			// The fd is always the first parameter of the enter event.
			//
			parinfo = evt->get_param(0);
			ASSERT(parinfo->m_len == sizeof(int64_t));
			ASSERT(evt->get_param_info(0)->type == PT_FD);

			evt->m_tinfo->m_lastevent_fd = *(int64_t *)parinfo->m_val;
		}
	}
	else
	{
		if(etype == evt->m_tinfo->m_lastevent_type + 1)
		{
			evt->m_tinfo->set_lastevent_data_validity(true);
		}
		else
		{
			evt->m_tinfo->set_lastevent_data_validity(false);
			return false;
		}

		if(eflags & EC_USES_FD)
		{
			evt->m_fdinfo = evt->m_tinfo->get_fd(evt->m_tinfo->m_lastevent_fd);
			if(evt->m_fdinfo == NULL)
			{
//              ASSERT(false);
				return false;
			}
		}
	}

	return true;
}

void sinsp_parser::store_event(sinsp_evt *evt)
{
	if(!evt->m_tinfo)
	{
		//
		// No thread in the table. We won't store this event, which mean that
		// we won't be able to parse the correspoding exit event and we'll have
		// to drop the information it carries.
		//
#ifdef GATHER_INTERNAL_STATS
		m_inspector->m_stats.m_n_store_drops++;
#endif
		return;
	}

	evt->m_tinfo->store_event(evt);

#ifdef GATHER_INTERNAL_STATS
	m_inspector->m_stats.m_n_stored_evts++;
#endif
}

bool sinsp_parser::retrieve_enter_event(sinsp_evt *enter_evt, sinsp_evt *exit_evt)
{
	//
	// Make sure there's a valid thread info
	//
	if(!exit_evt->m_tinfo)
	{
		ASSERT(false);
		return false;
	}

	//
	// Retrieve the copy of the enter event and initialize it
	//
	if(!exit_evt->m_tinfo->is_lastevent_data_valid())
	{
		//
		// This happen especially at the beginning of trace files, where events
		// can be truncated
		//
#ifdef GATHER_INTERNAL_STATS
		m_inspector->m_stats.m_n_retrieve_drops++;
#endif
		return false;
	}

	enter_evt->init(exit_evt->m_tinfo->m_lastevent_data, exit_evt->m_tinfo->m_lastevent_cpuid);

	//
	// Make sure that we're using the right enter event, to prevent inconsistencies when events
	// are dropped
	//
	if(enter_evt->get_type() != (exit_evt->get_type() - 1))
	{
		ASSERT(false);
		exit_evt->m_tinfo->set_lastevent_data_validity(false);
#ifdef GATHER_INTERNAL_STATS
		m_inspector->m_stats.m_n_retrieve_drops++;
#endif
		return false;
	}

#ifdef GATHER_INTERNAL_STATS
	m_inspector->m_stats.m_n_retrieved_evts++;
#endif
	return true;
}

///////////////////////////////////////////////////////////////////////////////
// PARSERS
///////////////////////////////////////////////////////////////////////////////
void sinsp_parser::parse_clone_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t tid = evt->get_tid();
	int64_t childtid;
	unordered_map<int64_t, sinsp_threadinfo>::iterator it;
	bool is_inverted_clone = false; // true if clone() in the child returns before the one in the parent
/*
if(evt->get_num() == 3837)
{
	int a = 0;
}
*/
	//
	// Validate the return value and get the child tid
	//
	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	childtid = *(int64_t *)parinfo->m_val;

	if(childtid < 0)
	{
		//
		// clone() failed. Do nothing and keep going.
		//
		return;
	}
	else if(childtid == 0)
	{
		//
		// clone() returns 0 in the child.
		// Validate that the child thread info has actually been created.
		//
		if(!evt->m_tinfo)
		{
			//
			// No thread yet.
			// This happens if
			//  - clone() returns in the child before than in the parent.
			//  - we dropped the clone exit event in the parent.
			// In both cases, we create the thread entry here
			is_inverted_clone = true;

			//
			// The tid to add is the one that generated this event
			//
			childtid = tid;

			//
			// Get the flags, and check if this is a thread or a new thread
			//
			parinfo = evt->get_param(7);
			ASSERT(parinfo->m_len == sizeof(int32_t));
			uint32_t flags = *(int32_t *)parinfo->m_val;

			if(flags & PPM_CL_CLONE_THREAD)
			{
				//
				// This is a thread, the parent tid is the pid
				//
				parinfo = evt->get_param(4);
				ASSERT(parinfo->m_len == sizeof(int64_t));
				tid = *(int64_t *)parinfo->m_val;
			}
			else
			{
				//
				// This is not a thread, the parent tid is ptid
				//
				parinfo = evt->get_param(5);
				ASSERT(parinfo->m_len == sizeof(int64_t));
				tid = *(int64_t *)parinfo->m_val;
			}

			//
			// Keep going and add the event with the standard code below
			//
		}
		else
		{
			return;
		}
	}

	//
	// Lookup the thread that called clone() so we can copy its information
	//
	sinsp_threadinfo* ptinfo = m_inspector->get_thread(tid, true);
	if(NULL == ptinfo)
	{
		//
		// No clone() caller, we probably missed earlier events.
		// We simply return and ignore the event, which means this thread won't be added to the table.
		//
		ASSERT(false);
		return;
	}

	//
	// See if the child is already there
	//
	sinsp_threadinfo* child = m_inspector->get_thread(childtid, false);
	if(NULL != child)
	{
		//
		// If this was an inverted clone, all is fine, we've already taken care
		// of adding the thread table entry in the child.
		// Otherwise, we assume that the entry is there because we missed the exit event
		// for a previous thread and we replace the info structure.
		//
		if(child->m_flags & PPM_CL_CLONE_INVERTED)
		{
			return;
		}
		else
		{
			ASSERT(false);
			m_inspector->remove_thread(childtid);
		}
	}

	//
	// Allocate the new thread info and initialize it
	// XXX this should absolutely not do a malloc, but get the item from a
	// preallocated list
	//
	sinsp_threadinfo tinfo(m_inspector);

	// Copy the command name from the parent
	tinfo.m_comm = ptinfo->m_comm;

	// Copy the full executable name from the parent
	tinfo.m_exe = ptinfo->m_exe;

	// Copy the command arguments from the parent
	tinfo.m_args = ptinfo->m_args;

	// Copy the pid
	parinfo = evt->get_param(4);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	tinfo.m_pid = *(int64_t *)parinfo->m_val;

	// Get the flags, and check if this is a thread or a new thread
	parinfo = evt->get_param(7);
	ASSERT(parinfo->m_len == sizeof(int32_t));
	tinfo.m_flags = *(int32_t *)parinfo->m_val;

	//
	// If clone()'s PPM_CL_CLONE_THREAD is not set it means that a new
	// thread was created. In that case, we set the pid to the one of the CHILD thread that
	// is going to be created.
	//
	if(!(tinfo.m_flags & PPM_CL_CLONE_THREAD))
	{
		tinfo.m_pid = childtid;
	}

	//
	// Copy the fd list
	// XXX this is a gross oversimplification that will need to be fixed.
	// What we do is: if the child is NOT a thread, we copy all the parent fds.
	// The right thing to do is looking at PPM_CL_CLONE_FILES, but there are
	// syscalls like open and pipe2 that can override PPM_CL_CLONE_FILES with the O_CLOEXEC flag
	//
	if(!(tinfo.m_flags & PPM_CL_CLONE_THREAD))
	{
		tinfo.m_fdtable = ptinfo->m_fdtable;

		//
		// It's important to reset the cache of the child thread, to prevent it from
		// referring to an element in the parent's table.
		//
		tinfo.m_fdtable.reset_cache();
	}
	//if((tinfo.m_flags & (PPM_CL_CLONE_FILES)))
	//{
	//    tinfo.m_fdtable = ptinfo.m_fdtable;
	//}

	if(is_inverted_clone)
	{
		tinfo.m_flags |= PPM_CL_CLONE_INVERTED;
	}

	// Copy the working directory
	parinfo = evt->get_param(6);
	tinfo.set_cwd(parinfo->m_val, parinfo->m_len);

	//
	// Add the new thread info to the table
	//
	tinfo.m_tid = childtid;
//	tinfo.m_ptid = ptinfo->m_pid;
	m_inspector->add_thread(tinfo);

	return;
}

void sinsp_parser::parse_execve_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;

	// Validate the return value
	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	retval = *(int64_t *)parinfo->m_val;

	if(retval < 0)
	{
		return;
	}

	//
	// We get here when execve returns. The thread has already been added by a previous fork or clone,
	// and we just update the entry with the new information.
	//
	if(!evt->m_tinfo)
	{
		//
		// No thread to update?
		// We probably missed the start event, so we will just do nothing
		//
		//fprintf(stderr, "comm = %s, args = %s\n",evt->get_param(1)->m_val,evt->get_param(1)->m_val);
		//ASSERT(false);
		return;
	}

	// Get the command name
	parinfo = evt->get_param(1);
	string tmps = parinfo->m_val;
	tmps = tmps.substr(tmps.rfind("/") + 1);
	evt->m_tinfo->m_comm = tmps;

	//
	// XXX We should retrieve the full executable name from the arguments that execve receives in the kernel,
	// but for the moment we don't do it, so we just copy the command name into the exe string
	//
	evt->m_tinfo->m_exe = parinfo->m_val;

	// Get the command arguments
	parinfo = evt->get_param(2);
	evt->m_tinfo->set_args(parinfo->m_val, parinfo->m_len);

	// Get the pid
	parinfo = evt->get_param(4);
	ASSERT(parinfo->m_len == sizeof(uint64_t));
	evt->m_tinfo->m_pid = *(uint64_t *)parinfo->m_val;

	// Get the working directory
	parinfo = evt->get_param(6);
	evt->m_tinfo->set_cwd(parinfo->m_val, parinfo->m_len);

	//
	// execve starts with a clean fd list, so we get rid of the fd list that clone
	// copied from the parent
	// XXX validate this
	//
	//  scap_fd_free_table(handle, tinfo);

	//
	// Clean the flags for this thread
	//
	evt->m_tinfo->m_flags = 0;
/*
	//
	// Clean the FD table
	//
	evt->m_tinfo->get_fd_table()->clear();
*/
	return;
}

void sinsp_parser::parse_open_openat_creat_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t fd;
	char *name;
	uint32_t namelen;
	uint32_t flags;
	//  uint32_t mode;
	sinsp_fdinfo fdi;
	sinsp_evt *enter_evt = &m_tmp_evt;
	string sdir;
	string tdirstr;

	//
	// Load the enter event so we can access its arguments
	//
	if(!retrieve_enter_event(enter_evt, evt))
	{
		return;
	}

	//
	// Check the return value
	//
	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	fd = *(int64_t *)parinfo->m_val;

	if(fd < 0)
	{
		//
		// The syscall failed. Nothing to add to the table.
		//
		return;
	}

	//
	// Parse the parameters, based on the event type
	//
	if(evt->get_type() == PPME_SYSCALL_OPEN_X)
	{
		parinfo = evt->get_param(1);
		name = parinfo->m_val;
		namelen = parinfo->m_len;

		parinfo = evt->get_param(2);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		flags = *(uint32_t *)parinfo->m_val;

		sdir = evt->m_tinfo->get_cwd();
	}
	else if(evt->get_type() == PPME_SYSCALL_CREAT_X)
	{
		parinfo = evt->get_param(1);
		name = parinfo->m_val;
		namelen = parinfo->m_len;

		flags = 0;

		sdir = evt->m_tinfo->get_cwd();
	}
	else if(evt->get_type() == PPME_SYSCALL_OPENAT_X)
	{
		parinfo = enter_evt->get_param(1);
		name = parinfo->m_val;
		namelen = parinfo->m_len;

		parinfo = enter_evt->get_param(2);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		flags = *(uint32_t *)parinfo->m_val;

		parinfo = enter_evt->get_param(0);
		ASSERT(parinfo->m_len == sizeof(int64_t));
		int64_t dirfd = *(int64_t *)parinfo->m_val;

		bool is_absolute = (name[0] == '/');

		if(is_absolute)
		{
			//
			// The path is absoulte.
			// Some processes (e.g. irqbalance) actually do this: they pass an invalid fd and
			// and bsolute path, and openat succeeds.
			//
			sdir = ".";
		}
		else if(dirfd == PPM_AT_FDCWD)
		{
			sdir = evt->m_tinfo->get_cwd();
		}
		else
		{
			evt->m_fdinfo = evt->m_tinfo->get_fd(dirfd);
			if(evt->m_fdinfo == NULL)
			{
				ASSERT(false);
				sdir = "<UNKNOWN>";
			}
			else
			{
				if(evt->m_fdinfo->m_name[evt->m_fdinfo->m_name.length()] == '/')
				{
					sdir = evt->m_fdinfo->m_name;
				}
				else
				{
					tdirstr = evt->m_fdinfo->m_name + '/';
					sdir = tdirstr;
				}
			}
		}
	}
	else
	{
		ASSERT(false);
		return;
	}

	// XXX not implemented yet
	//parinfo = evt->get_param(2);
	//ASSERT(parinfo->m_len == sizeof(uint32_t));
	//mode = *(uint32_t*)parinfo->m_val;

	//
	// Populate the new fdi
	//
	fdi.m_type = SCAP_FD_FILE;
	fdi.m_openflags = flags;
	fdi.add_filename(sdir.c_str(),
		sdir.length(),
		name,
		namelen);
	fdi.m_create_time = evt->get_ts();

	//
	// Add the fd to the table.
	//
	evt->m_tinfo->add_fd(fd, &fdi);

	//
	// Add this operation to the recend fd operations fifo
	//
	//  m_inspector->push_fdop(tid, &fdi, sinsp_fdop(fd, evt->get_type()));
}

//
// Helper function to allocate a socket fd, initialize it by parsing its parameters and add it to the fd table of the given thread.
//
inline void sinsp_parser::add_socket(sinsp_evt *evt, int64_t fd, uint32_t domain, uint32_t type, uint32_t protocol)
{
	sinsp_fdinfo fdi;

	//
	// Populate the new fdi
	//
	fdi.m_create_time = evt->get_ts();
	memset(&(fdi.m_info.m_ipv4info), 0, sizeof(fdi.m_info.m_ipv4info));
	fdi.m_type = SCAP_FD_UNKNOWN;
	fdi.m_info.m_ipv4info.m_fields.m_l4proto = SCAP_L4_UNKNOWN;

	if(domain == AF_UNIX)
	{
		fdi.set_type_unix_socket();
	}
	else if(domain == AF_INET)
	{
		fdi.m_type = SCAP_FD_IPV4_SOCK;

		if(protocol == IPPROTO_ICMP)
		{
			fdi.m_info.m_ipv4info.m_fields.m_l4proto = SCAP_L4_ICMP;
		}
		else if(protocol == IPPROTO_IP)
		{
			//
			// XXX: we mask type because, starting from linux 2.6.27, type can be ORed with
			//      SOCK_NONBLOCK and SOCK_CLOEXEC. We need to validate that byte masking is
			//      acceptable
			//
			if((type & 0xff) == SOCK_STREAM)
			{
				fdi.m_info.m_ipv4info.m_fields.m_l4proto = SCAP_L4_TCP;
			}
			else if((type & 0xff) == SOCK_DGRAM)
			{
				fdi.m_info.m_ipv4info.m_fields.m_l4proto = SCAP_L4_UDP;
			}
			else
			{
				ASSERT(false);
			}
		}
	}
	else
	{
		if(domain != 16 &&  // AF_NETLINK, used by processes to talk to the kernel
		        domain != 10 && // IPv6
		        domain != 17)   // AF_PACKET, used for packet capture
		{
			//
			// IPv6 will go here
			//
			ASSERT(false);
		}
	}

#ifndef INCLUDE_UNKNOWN_SOCKET_FDS
	if(fdi.m_type == SCAP_FD_UNKNOWN)
	{
		return;
	}
#endif

	//
	// Add the fd to the table.
	//
	evt->m_tinfo->add_fd(fd, &fdi);

	//
	// Add this operation to the recend fd operations fifo
	//
	//  m_inspector->push_fdop(tid, &fdi, sinsp_fdop(fd, PPME_SOCKET_SOCKET_X));
}

void sinsp_parser::parse_socket_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t fd;
	uint32_t domain;
	uint32_t type;
	uint32_t protocol;
	sinsp_evt *enter_evt = &m_tmp_evt;

	//
	// NOTE: we don't check the return value of scap_event_getparam() because we know the arguments we need are there.
	// XXX this extraction would be much faster if we parsed the event mnaually to extract the
	// parameters in one scan. We don't care too much because we assume that we get here
	// seldom enough that saving few tens of CPU cycles is not important.
	//
	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	fd = *(int64_t *)parinfo->m_val;

	if(fd < 0)
	{
		//
		// socket() failed. Nothing to add to the table.
		//
		return;
	}

	//
	// Load the enter event so we can access its arguments
	//
	if(!retrieve_enter_event(enter_evt, evt))
	{
		return;
	}

	//
	// Extract the arguments
	//
	parinfo = enter_evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(uint32_t));
	domain = *(uint32_t *)parinfo->m_val;

	parinfo = enter_evt->get_param(1);
	ASSERT(parinfo->m_len == sizeof(uint32_t));
	type = *(uint32_t *)parinfo->m_val;

	parinfo = enter_evt->get_param(2);
	ASSERT(parinfo->m_len == sizeof(uint32_t));
	protocol = *(uint32_t *)parinfo->m_val;

	//
	// Allocate a new fd descriptor, populate it and add it to the thread fd table
	//
	add_socket(evt, fd, domain, type, protocol);
}

void sinsp_parser::parse_bind_exit(sinsp_evt *evt)
{
	const char *parstr;

	if(evt->m_fdinfo == NULL)
	{
		return;
	}

	//
	// Mark this fd as a server
	//
	evt->m_fdinfo->set_role_server();
	evt->m_fdinfo->m_name = evt->get_param_as_str(1, &parstr, sinsp_evt::PF_SIMPLE);
}

void sinsp_parser::parse_connect_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t tid = evt->get_tid();
	char *packed_data;
	uint8_t family;
	unordered_map<int64_t, sinsp_fdinfo>::iterator fdit;
	const char *parstr;
	int64_t retval;

	if(evt->m_fdinfo == NULL)
	{
		return;
	}

	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(uint64_t));
	retval = *(int64_t*)parinfo->m_val;

	if(retval < 0)
	{
		//
		// connections that return with a SE_EINPROGRESS are totally legit.
		//
		if(retval != -SE_EINPROGRESS)
		{
			return;
		}
	}

	parinfo = evt->get_param(1);
	if(parinfo->m_len == 0)
	{
		//
		// No address, there's nothing we can really do with this.
		// This happens for socket types that we don't support, so we have the assertion
		// to make sure that this is not a type of socket that we support.
		//
		ASSERT(!(evt->m_fdinfo->is_unix_socket() || evt->m_fdinfo->is_ipv4_socket()));
		return;
	}

	packed_data = (char *)parinfo->m_val;

	//
	// Validate the family
	//
	family = *packed_data;

	if(family != AF_INET && family != AF_UNIX)
	{
		return;
	}

	//
	// Mark this fd as a client
	//
	evt->m_fdinfo->set_role_client();

	//
	// Fill the fd with the socket info
	//
	if(family == AF_INET)
	{
		if(evt->m_fdinfo->m_type != SCAP_FD_IPV4_SOCK)
		{
			//
			// This should happen only in case of a bug in our code, because I'm assuming that the OS
			// causes a connect with the wrong socket type to fail.
			// Assert in debug mode and just keep going in release mode.
			//
			ASSERT(false);
		}

		//
		// UDP sockets can have an arbitrary number of connects, and each new one overrides
		// the previous one.
		//
		sinsp_connection* conn = m_inspector->m_ipv4_connections->get_connection(
			evt->m_fdinfo->m_info.m_ipv4info,
			evt->get_ts());

		if(conn)
		{
			if(conn->m_analysis_flags == sinsp_connection::AF_CLOSED)
			{
				//
				// There is a closed connection with the same key. We drop its content and reuse it.
				// We also mark it as reused so that the analyzer is aware of it
				//
				conn->reset();
				conn->m_analysis_flags = sinsp_connection::AF_REUSED;
			}

			ASSERT(evt->m_fdinfo->m_info.m_ipv4info.m_fields.m_l4proto == SCAP_L4_UDP);
			m_inspector->m_ipv4_connections->remove_connection(
				evt->m_fdinfo->m_info.m_ipv4info);
		}

		//
		// Update the FD with this tuple
		//
		set_addresses_and_ports(evt->m_fdinfo, packed_data);
		//evt->m_fdinfo->m_info.m_ipv4info.m_fields.m_l4proto = SCAP_L4_TCP;

		//
		// Add the friendly name to the fd info
		//
		evt->m_fdinfo->m_name = evt->get_param_as_str(1, &parstr, sinsp_evt::PF_SIMPLE);

		//
		// Add the tuple to the connection table
		//
		m_inspector->m_ipv4_connections->add_connection(evt->m_fdinfo->m_info.m_ipv4info,
		        evt->m_tinfo,
		        tid,
		        evt->m_tinfo->m_lastevent_fd,
		        true,
		        evt->get_ts());

		return;
	}
	else
	{
		if(!evt->m_fdinfo->is_unix_socket())
		{
			//
			// This should happen only in case of a bug in our code, because I'm assuming that the OS
			// causes a connect with the wrong socket type to fail.
			// Assert in debug mode and just keep going in release mode.
			//
			ASSERT(false);
		}

		set_unix_info(evt->m_fdinfo, packed_data);

		m_inspector->m_unix_connections->add_connection(evt->m_fdinfo->m_info.m_unixinfo,
		        evt->m_tinfo,
		        tid,
		        evt->m_tinfo->m_lastevent_fd,
		        true,
		        evt->get_ts());
		evt->m_fdinfo->m_name = evt->get_param_as_str(1, &parstr, sinsp_evt::PF_SIMPLE);
	}

	//
	// Add this operation to the recend fd operations fifo
	//
	//  m_inspector->push_fdop(tid, evt->m_fdinfo, sinsp_fdop(fd, evt->get_type()));
}

void sinsp_parser::parse_accept_exit(sinsp_evt *evt, bool is_accept4)
{
	sinsp_evt_param *parinfo;
	int64_t tid = evt->get_tid();
	int64_t fd;
	char *packed_data;
	uint8_t family;
	unordered_map<int64_t, sinsp_fdinfo>::iterator fdit;
	sinsp_fdinfo fdi;
	const char *parstr;

	//
	// Lookup the thread
	//
	if(!evt->m_tinfo)
	{
		ASSERT(false);
		return;
	}

	//
	// Extract the fd
	//
	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	fd = *(int64_t *)parinfo->m_val;

	if(fd < 0)
	{
		//
		// This was a failed connect.
		// Do nothing.
		//
		return;
	}

	parinfo = evt->get_param(1);
	if(parinfo->m_len == 0)
	{
		//
		// No address, there's nothing we can really do with this.
		// This happens for socket types that we don't support, so we have the assertion
		// to make sure that this is not a type of socket that we support.
		//
		ASSERT(!(evt->m_fdinfo->is_unix_socket() || evt->m_fdinfo->is_ipv4_socket()));
		return;
	}

	packed_data = (char *)parinfo->m_val;

	//
	// Validate the family
	//
	family = *packed_data;

	if(family != AF_INET && family != AF_UNIX)
	{
		return;
	}

	//
	// Populate the fd info class
	//
	if(*packed_data == AF_INET)
	{
		fdi.m_type = SCAP_FD_IPV4_SOCK;
		set_addresses_and_ports(&fdi, packed_data);
		fdi.m_info.m_ipv4info.m_fields.m_l4proto = SCAP_L4_TCP;

		//
		// Add the tuple to the connection table
		//
		m_inspector->m_ipv4_connections->add_connection(fdi.m_info.m_ipv4info,
		        evt->m_tinfo,
		        tid,
		        fd,
		        false,
		        evt->get_ts());
	}
	else
	{
		fdi.set_type_unix_socket();
		set_unix_info(&fdi, packed_data);
		m_inspector->m_unix_connections->add_connection(fdi.m_info.m_unixinfo,
		        evt->m_tinfo,
		        tid,
		        fd,
		        false,
		        evt->get_ts());
	}

	fdi.m_name = evt->get_param_as_str(1, &parstr, sinsp_evt::PF_SIMPLE);
	fdi.m_create_time = evt->get_ts();
	fdi.m_flags = 0;

	//
	// Mark this fd as a server
	//
	fdi.set_role_server();
	fdi.set_is_transaction();
/*
	//
	// Sometimes this syscall can be called on an FD that is being closed (i.e
	// the close enter has arrived but the close exit has not arrived yet). 
	// If this is the case, mark the FD so that the successive close exit won't
	// destroy it.
	//
	sinsp_fdinfo* fdinfo = evt->m_tinfo->get_fd(fd);
	if(fdinfo != NULL)
	{
		if(fdinfo->m_flags & sinsp_fdinfo::FLAGS_CLOSE_IN_PROGRESS)
		{
			fdi.m_flags |= sinsp_fdinfo::FLAGS_CLOSE_CANCELED;
		}
		else
		{
			ASSERT(false);
		}
	}
*/
	//
	// Add the entry to the table
	//
	evt->m_tinfo->add_fd(fd, &fdi);
}

void sinsp_parser::parse_close_enter(sinsp_evt *evt)
{
	if(!evt->m_tinfo)
	{
		return;
	}

	evt->m_fdinfo = evt->m_tinfo->get_fd(evt->m_tinfo->m_lastevent_fd);
	if(evt->m_fdinfo == NULL)
	{
		return;
	}

	evt->m_fdinfo->m_flags |= sinsp_fdinfo::FLAGS_CLOSE_IN_PROGRESS;
}

void sinsp_parser::parse_close_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;
	int64_t tid = evt->get_tid();

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	//
	// If the close() was successful, do the cleanup
	//
	if(retval >= 0)
	{
		if(evt->m_fdinfo == NULL)
		{
			return;
		}

		//
		// a close gets canceled when the same fd is created succesfully between
		// close enter and close exit.
		//
		if(evt->m_fdinfo->m_flags & sinsp_fdinfo::FLAGS_CLOSE_CANCELED)
		{
			return;
		}

		//m_inspector->push_fdop(tid, evt->m_fdinfo, sinsp_fdop(fd, evt->get_type()));

		//
		// Schedule the fd for removal
		//
		m_inspector->m_tid_of_fd_to_remove = evt->get_tid();
		m_inspector->m_fd_to_remove = evt->m_tinfo->m_lastevent_fd;

		//
		// If the fd is in the transaction table, get rid of it there too
		//
		if(evt->m_fdinfo->is_transaction())
		{
			sinsp_transaction_manager *pttable = evt->m_tinfo->get_transaction_manager();
			pttable->remove_transaction(tid, evt->m_tinfo->m_lastevent_fd, evt->get_ts());
		}

		//
		// If the fd is in the connection table, schedule the connection for removal
		//
		if(evt->m_fdinfo->is_tcp_socket() && 
			!evt->m_fdinfo->has_no_role() &&
			!(evt->m_fdinfo->m_info.m_ipv4info.m_fields.m_l4proto == 0))
		{
#ifdef USE_ANALYZER
			m_inspector->m_ipv4_connections->remove_connection(evt->m_fdinfo->m_info.m_ipv4info, false);
#else
			m_inspector->m_ipv4_connections->remove_connection(evt->m_fdinfo->m_info.m_ipv4info);
#endif
		}
		else if(evt->m_fdinfo->is_unix_socket() && 
			!evt->m_fdinfo->has_no_role() &&
			!(evt->m_fdinfo->m_info.m_unixinfo.m_fields.m_source == 0 && evt->m_fdinfo->m_info.m_unixinfo.m_fields.m_source ==  0))
		{
#ifdef USE_ANALYZER
			m_inspector->m_unix_connections->remove_connection(evt->m_fdinfo->m_info.m_unixinfo, false);
#else
			m_inspector->m_unix_connections->remove_connection(evt->m_fdinfo->m_info.m_unixinfo);
#endif
		}
	}
	else
	{
		//
		// It is normal when a close fails that the fd lookup failed, so we revert the
		// increment of m_n_failed_fd_lookups (for the enter event too if there's one).
		//
#ifdef GATHER_INTERNAL_STATS
		m_inspector->m_stats.m_n_failed_fd_lookups--;
#endif
		if(evt->m_tinfo && evt->m_tinfo->is_lastevent_data_valid())
		{
#ifdef GATHER_INTERNAL_STATS
			m_inspector->m_stats.m_n_failed_fd_lookups--;
#endif
		}
	}
}

void sinsp_parser::add_pipe(sinsp_evt *evt, int64_t tid, int64_t fd, uint64_t ino)
{
	sinsp_fdinfo fdi;

	//
	// lookup the thread info
	//
	if(!evt->m_tinfo)
	{
		return;
	}

	//
	// Populate the new fdi
	//
	fdi.m_type = SCAP_FD_FIFO;
	fdi.m_name = "";
	fdi.m_ino = ino;

	//
	// Add the fd to the table.
	//
	evt->m_tinfo->add_fd(fd, &fdi);
}

void sinsp_parser::parse_socketpair_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t fd1, fd2;
	int64_t retval;
	uint64_t source_address;
	uint64_t peer_address;

	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	if(retval < 0)
	{
		//
		// socketpair() failed. Nothing to add to the table.
		//
		return;
	}

	parinfo = evt->get_param(1);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	fd1 = *(int64_t *)parinfo->m_val;

	parinfo = evt->get_param(2);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	fd2 = *(int64_t *)parinfo->m_val;

	parinfo = evt->get_param(3);
	ASSERT(parinfo->m_len == sizeof(uint64_t));
	source_address = *(uint64_t *)parinfo->m_val;

	parinfo = evt->get_param(4);
	ASSERT(parinfo->m_len == sizeof(uint64_t));
	peer_address = *(uint64_t *)parinfo->m_val;

	sinsp_fdinfo fdi;
	fdi.set_type_unix_socket();
	fdi.m_info.m_unixinfo.m_fields.m_source = source_address;
	fdi.m_info.m_unixinfo.m_fields.m_dest = peer_address;
	evt->m_tinfo->add_fd(fd1, &fdi);
	evt->m_tinfo->add_fd(fd2, &fdi);
}

void sinsp_parser::parse_pipe_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t fd1, fd2;
	int64_t retval;
	uint64_t ino;

	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	if(retval < 0)
	{
		//
		// pipe() failed. Nothing to add to the table.
		//
		return;
	}

	parinfo = evt->get_param(1);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	fd1 = *(int64_t *)parinfo->m_val;

	parinfo = evt->get_param(2);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	fd2 = *(int64_t *)parinfo->m_val;

	parinfo = evt->get_param(3);
	ASSERT(parinfo->m_len == sizeof(uint64_t));
	ino = *(uint64_t *)parinfo->m_val;

	add_pipe(evt, evt->get_tid(), fd1, ino);
	add_pipe(evt, evt->get_tid(), fd2, ino);
}


void sinsp_parser::parse_thread_exit(sinsp_evt *evt)
{
	if(evt->m_tinfo)
	{
#ifdef USE_ANALYZER
		evt->m_tinfo->m_analysis_flags |= sinsp_threadinfo::AF_CLOSED;
#else
		m_inspector->m_tid_to_remove = evt->get_tid();
#endif
	}
}

void sinsp_parser::handle_read(sinsp_evt *evt, int64_t tid, int64_t fd, char *data, uint32_t len)
{
	if(evt->m_fdinfo->is_ipv4_socket() || evt->m_fdinfo->is_unix_socket())
	{
		if(evt->m_fdinfo->is_unix_socket())
		{
			// ignore invalid destination addresses
			if(0 == evt->m_fdinfo->m_info.m_unixinfo.m_fields.m_dest)
			{
				return;
			}

			sinsp_connection *connection = m_inspector->get_connection(evt->m_fdinfo->m_info.m_unixinfo, evt->get_ts());
			if(connection == NULL)
			{
				//
				// We dropped the accept() or connect()
				// Create a connection entry here and make an assumption this is the server FD.
				// (we assume that a server usually starts with a read).
				//
				evt->m_fdinfo->set_role_server();
				m_inspector->m_unix_connections->add_connection(evt->m_fdinfo->m_info.m_unixinfo,
				        evt->m_tinfo,
				        tid,
				        fd,
				        evt->m_fdinfo->has_role_client(),
				        evt->get_ts());
			}
			else if(fd != connection->m_sfd && fd != connection->m_dfd)
			{
				//
				// We dropped both accept() and connect(), and the connection has already been established
				// when handling a read on the other side.
				//
				if(connection->m_analysis_flags == sinsp_connection::AF_CLOSED)
				{
					//
					// There is a closed connection with the same key. We drop its content and reuse it.
					// We also mark it as reused so that the analyzer is aware of it
					//
					connection->reset();
					connection->m_analysis_flags = sinsp_connection::AF_REUSED;
				}
				else
				{
					if(connection->is_server_only())
					{
						evt->m_fdinfo->set_role_client();
					}
					else if(connection->is_client_only())
					{
						evt->m_fdinfo->set_role_server();
					}
					else
					{
						//
						// FDs don't match but the connection has not been closed yet.
						// This seem to heppen with unix sockets, whose addresses are reused when 
						// just on of the endpoints has been closed.
						// Jusr recycle the connection.
						//
						connection->reset();
						connection->m_analysis_flags = sinsp_connection::AF_REUSED;
					}
				}

				m_inspector->m_unix_connections->add_connection(evt->m_fdinfo->m_info.m_unixinfo,
						evt->m_tinfo,
						tid,
						fd,
						evt->m_fdinfo->has_role_client(),
						evt->get_ts());
			}


			if(evt->m_fdinfo->has_role_server())
			{
				evt->m_fdinfo->set_is_transaction();
			}
		}
		else if(evt->m_fdinfo->is_tcp_socket())
		{
			sinsp_connection *connection = m_inspector->get_connection(evt->m_fdinfo->m_info.m_ipv4info, evt->get_ts());
			if(connection == NULL)
			{
				//
				// We dropped the accept() or connect()
				// Create a connection entry here and make an assumption this is the server FD.
				// (we assume that a server usually starts with a read).
				//
				evt->m_fdinfo->set_role_server();
				m_inspector->m_ipv4_connections->add_connection(evt->m_fdinfo->m_info.m_ipv4info,
				        evt->m_tinfo,
				        tid,
				        fd,
				        evt->m_fdinfo->has_role_client(),
				        evt->get_ts());
			}
			else if(fd != connection->m_sfd && fd != connection->m_dfd)
			{
				//
				// We dropped both accept() and connect(), and the connection has already been established
				// when handling a read on the other side.
				//
				if(connection->m_analysis_flags == sinsp_connection::AF_CLOSED)
				{
					//
					// There is a closed connection with the same key. We drop its content and reuse it.
					// We also mark it as reused so that the analyzer is aware of it
					//
					connection->reset();
					connection->m_analysis_flags = sinsp_connection::AF_REUSED;
				}
				else
				{
					if(connection->is_server_only())
					{
						evt->m_fdinfo->set_role_client();
					}
					else if(connection->is_client_only())
					{
						evt->m_fdinfo->set_role_server();
					}
					else
					{
						//
						// FDs don't match but the connection has not been closed yet.
						// This can happen in case of event drops.
						//
						connection->reset();
						connection->m_analysis_flags = sinsp_connection::AF_REUSED;
					}
				}

				m_inspector->m_ipv4_connections->add_connection(evt->m_fdinfo->m_info.m_ipv4info,
						evt->m_tinfo,
						tid,
						fd,
						evt->m_fdinfo->has_role_client(),
						evt->get_ts());
			}


			if(evt->m_fdinfo->has_role_server())
			{
				evt->m_fdinfo->set_is_transaction();
			}
		}

		if(evt->m_fdinfo->has_role_server())
		{
			//
			// See if there's already a transaction
			//
			sinsp_transaction_manager *pttable = evt->m_tinfo->get_transaction_manager();

			sinsp_partial_transaction *trinfo = pttable->get_transaction(fd);
			if(trinfo == NULL)
			{
				//
				// No transaction yet.
				//
				sinsp_partial_transaction *newtrinfo;
				if(evt->m_fdinfo->is_unix_socket())
				{
					newtrinfo = pttable->add_transaction(fd, &evt->m_fdinfo->m_info.m_unixinfo);
				}
				else
				{
					newtrinfo = pttable->add_transaction(fd, &evt->m_fdinfo->m_info.m_ipv4info);
				}

				if(!newtrinfo)
				{
					ASSERT(false);
					return;
				}

				//
				// Try to parse this as HTTP
				//
				if(m_http_parser.is_msg_http(data, len) && m_http_parser.parse_request(data, len))
				{
					//
					// Success. Add an HTTP entry to the transaction table for this fd
					//
					newtrinfo->m_type = sinsp_partial_transaction::TYPE_HTTP;
					newtrinfo->m_protoinfo.push_back(m_http_parser.m_url);
					newtrinfo->m_protoinfo.push_back(m_http_parser.m_agent);
				}
				else
				{
					//
					// The message has not been recognized as HTTP.
					// Add an IP entry to the transaction table for this fd
					//
					newtrinfo->m_type = sinsp_partial_transaction::TYPE_IP;
				}

				trinfo = newtrinfo;
			}

			//
			// There is already a transaction. Update its state.
			//
			trinfo->update(evt->m_tinfo->m_lastevent_ts, evt->get_ts(), tid, sinsp_partial_transaction::DIR_IN, len);
		}
	}
	else if(evt->m_fdinfo->is_pipe())
	{
		sinsp_connection *connection = m_inspector->get_connection(evt->m_fdinfo->m_ino, evt->get_ts());
		if(NULL == connection || connection->is_server_only())
		{
			m_inspector->m_pipe_connections->add_connection(evt->m_fdinfo->m_ino,
			        evt->m_tinfo,
			        tid,
			        fd,
			        true,
			        evt->get_ts());
		}
	}
}

void sinsp_parser::handle_write(sinsp_evt *evt, int64_t tid, int64_t fd, char *data, uint32_t len)
{
	if(evt->m_fdinfo->is_ipv4_socket() || evt->m_fdinfo->is_unix_socket())
	{
		if(evt->m_fdinfo->is_unix_socket())
		{
			// ignore invalid destination addresses
			if(0 == evt->m_fdinfo->m_info.m_unixinfo.m_fields.m_dest)
			{
				return;
			}

			sinsp_connection *connection = m_inspector->get_connection(evt->m_fdinfo->m_info.m_unixinfo, evt->get_ts());
			if(connection == NULL)
			{
				//
				// We dropped the accept() or connect()
				// Create a connection entry here and make an assumption this is the client FD
				// (we assume that a client usually starts with a write)
				//
				evt->m_fdinfo->set_role_client();
				m_inspector->m_unix_connections->add_connection(evt->m_fdinfo->m_info.m_unixinfo,
				        evt->m_tinfo,
				        tid,
				        fd,
				        evt->m_fdinfo->has_role_client(),
				        evt->get_ts());
			}
			else if(fd != connection->m_sfd && fd != connection->m_dfd)
			{
				//
				// We dropped both accept() and connect(), and the connection has already been established
				// when handling a read on the other side.
				//
				if(connection->m_analysis_flags == sinsp_connection::AF_CLOSED)
				{
					//
					// There is a closed connection with the same key. We drop its content and reuse it.
					// We also mark it as reused so that the analyzer is aware of it
					//
					connection->reset();
					connection->m_analysis_flags = sinsp_connection::AF_REUSED;
				}
				else
				{
					if(connection->is_server_only())
					{
						evt->m_fdinfo->set_role_client();
					}
					else if(connection->is_client_only())
					{
						evt->m_fdinfo->set_role_server();
					}
					else
					{
						//
						// FDs don't match but the connection has not been closed yet.
						// This seem to heppen with unix sockets, whose addresses are reused when 
						// just on of the endpoints has been closed.
						// Jusr recycle the connection.
						//
						connection->reset();
						connection->m_analysis_flags = sinsp_connection::AF_REUSED;
					}
				}

				m_inspector->m_unix_connections->add_connection(evt->m_fdinfo->m_info.m_unixinfo,
						evt->m_tinfo,
						tid,
						fd,
						evt->m_fdinfo->has_role_client(),
						evt->get_ts());
			}
		}
		else if(evt->m_fdinfo->is_tcp_socket())
		{
			sinsp_connection *connection = m_inspector->get_connection(evt->m_fdinfo->m_info.m_ipv4info, evt->get_ts());
			if(connection == NULL)
			{
				//
				// We dropped the accept() or connect()
				// Create a connection entry here and make an assumption this is the client FD
				// (we assume that a client usually starts with a write)
				//
				evt->m_fdinfo->set_role_client();
				m_inspector->m_ipv4_connections->add_connection(evt->m_fdinfo->m_info.m_ipv4info,
				        evt->m_tinfo,
				        tid,
				        fd,
				        evt->m_fdinfo->has_role_client(),
				        evt->get_ts());
			}
			else if(fd != connection->m_sfd && fd != connection->m_dfd)
			{
				//
				// We dropped both accept() and connect(), and the connection has already been established
				// when handling a read on the other side.
				//
				if(connection->m_analysis_flags == sinsp_connection::AF_CLOSED)
				{
					//
					// There is a closed connection with the same key. We drop its content and reuse it.
					// We also mark it as reused so that the analyzer is aware of it
					//
					connection->reset();
					connection->m_analysis_flags = sinsp_connection::AF_REUSED;
				}
				else
				{
					if(connection->is_server_only())
					{
						evt->m_fdinfo->set_role_client();
					}
					else if(connection->is_client_only())
					{
						evt->m_fdinfo->set_role_server();
					}
					else
					{
						//
						// FDs don't match but the connection has not been closed yet.
						// This can happen in case of event drops.
						//
						connection->reset();
						connection->m_analysis_flags = sinsp_connection::AF_REUSED;
					}
				}

				m_inspector->m_ipv4_connections->add_connection(evt->m_fdinfo->m_info.m_ipv4info,
						evt->m_tinfo,
						tid,
						fd,
						evt->m_fdinfo->has_role_client(),
						evt->get_ts());
			}
		}

		if(evt->m_fdinfo->has_role_server())
		{
			//
			// See if there's already a transaction
			//
			sinsp_transaction_manager *pttable = evt->m_tinfo->get_transaction_manager();

			sinsp_partial_transaction *trinfo = pttable->get_transaction(fd);
			if(trinfo == NULL)
			{
				//
				// No transaction yet.
				//
				sinsp_partial_transaction *newtrinfo;
				if(evt->m_fdinfo->is_unix_socket())
				{
					newtrinfo = pttable->add_transaction(fd, &evt->m_fdinfo->m_info.m_unixinfo);
				}
				else
				{
					newtrinfo = pttable->add_transaction(fd, &evt->m_fdinfo->m_info.m_ipv4info);
				}

				if(!newtrinfo)
				{
					ASSERT(false);
					return;
				}

				//
				// For the moment, we assume that a transaction that starts with
				// a write is just IP.
				// Stuff like mysql starts with a write
				//
				newtrinfo->m_type = sinsp_partial_transaction::TYPE_IP;

				trinfo = newtrinfo;
			}

			//
			// There is already a transaction. Update its state.
			//
			trinfo->update(evt->m_tinfo->m_lastevent_ts, evt->get_ts(), tid, sinsp_partial_transaction::DIR_OUT, len);
		}
	}
	else if(evt->m_fdinfo->is_pipe())
	{
		sinsp_connection *connection = m_inspector->get_connection(evt->m_fdinfo->m_ino, evt->get_ts());

		if(NULL == connection || connection->is_client_only())
		{
			m_inspector->m_pipe_connections->add_connection(evt->m_fdinfo->m_ino,
			        evt->m_tinfo,
			        tid,
			        fd,
			        false,
			        evt->get_ts());
		}
	}
}

void sinsp_parser::set_addresses_and_ports(sinsp_fdinfo *fdinfo, char *packed_data)
{
	fdinfo->m_info.m_ipv4info.m_fields.m_sip = *(uint32_t *)(packed_data + 1);
	fdinfo->m_info.m_ipv4info.m_fields.m_sport = *(uint16_t *)(packed_data + 5);
	fdinfo->m_info.m_ipv4info.m_fields.m_dip = *(uint32_t *)(packed_data + 7);
	fdinfo->m_info.m_ipv4info.m_fields.m_dport = *(uint16_t *)(packed_data + 11);
}

void sinsp_parser::set_unix_info(sinsp_fdinfo *fdinfo, char *packed_data)
{
	fdinfo->m_info.m_unixinfo.m_fields.m_source = *(uint64_t *)(packed_data + 1);
	fdinfo->m_info.m_unixinfo.m_fields.m_dest = *(uint64_t *)(packed_data + 9);
}


void sinsp_parser::update_fd(sinsp_evt *evt, sinsp_evt_param *parinfo)
{
	char *packed_data = parinfo->m_val;
	uint8_t family = *packed_data;
	if(family == AF_INET)
	{
		evt->m_fdinfo->m_type = SCAP_FD_IPV4_SOCK;
		set_addresses_and_ports(evt->m_fdinfo, packed_data);
		evt->m_fdinfo->m_info.m_ipv4info.m_fields.m_l4proto = SCAP_L4_UDP;
		m_inspector->m_network_interfaces->update_fd(evt->m_fdinfo);
	}
}

void sinsp_parser::parse_rw_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;
	int64_t tid = evt->get_tid();
	sinsp_evt *enter_evt = &m_tmp_evt;

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	retval = *(int64_t *)parinfo->m_val;

	//
	// If the operation was successful, validate that the fd exists
	//
	if(retval >= 0)
	{
		if(!evt->m_fdinfo)
		{
			return;
		}

		uint16_t etype = evt->get_type();

		if(etype == PPME_SYSCALL_READ_X ||
		        etype == PPME_SOCKET_RECV_X ||
		        etype == PPME_SOCKET_RECVFROM_X ||
		        etype == PPME_SYSCALL_PREAD_X ||
		        etype == PPME_SYSCALL_READV_X ||
		        etype == PPME_SYSCALL_PREADV_X)
		{
			char *data;
			uint32_t datalen;

			if(etype == PPME_SOCKET_RECVFROM_X && (evt->m_fdinfo->m_name.length() == 0 || evt->m_fdinfo->is_udp_socket()))
			{
				//
				// recvfrom contains tuple info.
				// If the fd still doesn't contain tuple info (because the socket is a
				// datagram one or because some event was lost),
				// add it here.
				//

				update_fd(evt, evt->get_param(2));
				const char *parstr;
				if(evt->m_fdinfo->m_name.length() == 0)
				{
					evt->m_fdinfo->m_name = evt->get_param_as_str(2, &parstr, sinsp_evt::PF_SIMPLE);
				}
				if(evt->m_fdinfo->has_role_server())
				{
					evt->m_fdinfo->set_is_transaction();
				}
			}

			//
			// Extract the data buffer
			//
			if(etype == PPME_SYSCALL_READV_X || etype == PPME_SYSCALL_PREADV_X)
			{
				parinfo = evt->get_param(2);
			}
			else
			{
				parinfo = evt->get_param(1);
			}

			datalen = parinfo->m_len;
			data = parinfo->m_val;

			handle_read(evt, tid, evt->m_tinfo->m_lastevent_fd, data, datalen);
		}
		else
		{
			char *data;
			uint32_t datalen;

			if(etype == PPME_SOCKET_SENDTO_X && evt->m_fdinfo->m_name.length() == 0)
			{
				//
				// sendto contains tuple info in the enter event.
				// If the fd still doesn't contain tuple info (because the socket is a datagram one or because some event was lost),
				// add it here.
				//
				if(!retrieve_enter_event(enter_evt, evt))
				{
					return;
				}

				const char *parstr;
				update_fd(evt, enter_evt->get_param(2));
				evt->m_fdinfo->m_name = enter_evt->get_param_as_str(2, &parstr, sinsp_evt::PF_SIMPLE);
			}

			//
			// Extract the data buffer
			//
			parinfo = evt->get_param(1);
			datalen = parinfo->m_len;
			data = parinfo->m_val;

			handle_write(evt, tid, evt->m_tinfo->m_lastevent_fd, data, datalen);
		}

		//
		// Add this operation to the recend fd operations fifo
		//
		//      m_inspector->push_fdop(tid, evt->m_fdinfo, sinsp_fdop(fd, evt->get_type()));
	}
}

//
// XXX this is not really implemented yet
//
void sinsp_parser::parse_fstat_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	//
	// If the operation was successful, validate that the fd exists
	//
	if(retval >= 0)
	{
		if(!evt->m_fdinfo)
		{
			return;
		}

		//
		// Add this operation to the recend fd operations fifo
		//
		//      m_inspector->push_fdop(tid, evt->m_fdinfo, sinsp_fdop(fd, evt->get_type()));
	}
}

void sinsp_parser::parse_eventfd_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t fd;
	sinsp_fdinfo fdi;

	//
	// lookup the thread info
	//
	if(!evt->m_tinfo)
	{
		ASSERT(false);
		return;
	}

	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	fd = *(int64_t *)parinfo->m_val;

	if(fd < 0)
	{
		//
		// eventfd() failed. Nothing to add to the table.
		//
		return;
	}

	//
	// Populate the new fdi
	//
	fdi.m_type = SCAP_FD_EVENT;
	fdi.m_name = "";

	//
	// Add the fd to the table.
	//
	evt->m_tinfo->add_fd(fd, &fdi);
}

void sinsp_parser::parse_chdir_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	//
	// In case of success, update the thread working dir
	//
	if(retval >= 0)
	{
		sinsp_evt_param *parinfo;

		// Update the thread working directory
		parinfo = evt->get_param(1);
		evt->m_tinfo->set_cwd(parinfo->m_val, parinfo->m_len);
	}
}

void sinsp_parser::parse_fchdir_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	//
	// In case of success, update the thread working dir
	//
	if(retval >= 0)
	{
		//
		// Find the fd name
		//
		if(evt->m_fdinfo == NULL)
		{
			return;
		}

		// Update the thread working directory
		evt->m_tinfo->set_cwd((char *)evt->m_fdinfo->m_name.c_str(),
		                 evt->m_fdinfo->m_name.size());
	}
}

void sinsp_parser::parse_getcwd_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;

	if(!evt->m_tinfo)
	{
		//
		// No thread in the table. We won't store this event, which mean that
		// we won't be able to parse the correspoding exit event and we'll have
		// to drop the information it carries.
		//
		ASSERT(false);
		return;
	}

	parinfo = evt->get_param(1);

#ifdef _DEBUG
	string chkstr = string(parinfo->m_val);

	if(chkstr != "/")
	{
		if(chkstr + "/"  != evt->m_tinfo->get_cwd())
		{
			//
			// This shouldn't happen, because we should be able to stay in synch by
			// following chdir(). If it does, it's almost sure there was an event drop.
			// In that case, we use this value to update the thread cwd.
			//
			ASSERT(false);
		}
	}
#endif

	evt->m_tinfo->set_cwd(parinfo->m_val, parinfo->m_len);
}

void sinsp_parser::parse_shutdown_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;
	int64_t tid = evt->get_tid();

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	retval = *(int64_t *)parinfo->m_val;

	//
	// If the close() was successful, do the cleanup
	//
	if(retval >= 0)
	{
		if(evt->m_fdinfo == NULL)
		{
			return;
		}

		//
		// If the fd is in the transaction table, get rid of it there
		//
		sinsp_transaction_manager *pttable = evt->m_tinfo->get_transaction_manager();

		if(evt->m_fdinfo->is_transaction())
		{
			pttable->remove_transaction(tid,
			                            evt->m_tinfo->m_lastevent_fd,
			                            evt->get_ts());
		}
	}
}

void sinsp_parser::parse_dup_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	//
	// Check if the syscall was successful
	//
	if(retval >= 0)
	{
		if(evt->m_fdinfo == NULL)
		{
			return;
		}

		//
		// Temporarily change the creation time of the old FD, so that the new one
		// goes in the table with the right time
		//
		uint64_t ttime = evt->m_fdinfo->m_create_time;
		evt->m_fdinfo->m_create_time = evt->get_ts();

		//
		// Add the new fd to the table.
		// NOTE: dup2 and dup3 accept an existing FD and in that case they close it.
		//       For us it's ok to just overwrite it.
		//
		evt->m_tinfo->add_fd(retval, evt->m_fdinfo);

		//
		// Restore the original time in the old fd
		//
		if(retval != evt->m_tinfo->m_lastevent_fd)
		{
			evt->m_fdinfo->m_create_time = ttime;
		}
	}
}

void sinsp_parser::parse_signalfd_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	//
	// Check if the syscall was successful
	//
	if(retval >= 0)
	{
		sinsp_fdinfo fdi;

		//
		// Populate the new fdi
		//
		fdi.m_type = SCAP_FD_SIGNALFD;
		fdi.m_name = "";
		fdi.m_create_time = evt->get_ts();

		//
		// Add the fd to the table.
		//
		evt->m_tinfo->add_fd(retval, &fdi);
	}
}

void sinsp_parser::parse_timerfd_create_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	//
	// Check if the syscall was successful
	//
	if(retval >= 0)
	{
		sinsp_fdinfo fdi;

		//
		// Populate the new fdi
		//
		fdi.m_type = SCAP_FD_TIMERFD;
		fdi.m_name = "";
		fdi.m_create_time = evt->get_ts();

		//
		// Add the fd to the table.
		//
		evt->m_tinfo->add_fd(retval, &fdi);
	}
}

void sinsp_parser::parse_inotify_init_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	//
	// Check if the syscall was successful
	//
	if(retval >= 0)
	{
		sinsp_fdinfo fdi;

		//
		// Populate the new fdi
		//
		fdi.m_type = SCAP_FD_INOTIFY;
		fdi.m_name = "";
		fdi.m_create_time = evt->get_ts();

		//
		// Add the fd to the table.
		//
		evt->m_tinfo->add_fd(retval, &fdi);
	}
}
