#ifndef _WIN32
#include <unistd.h>
#endif

#include "sinsp.h"
#include "sinsp_int.h"
#include "sinsp_errno.h"
#include "sinsp_signal.h"
#include "filter.h"
#include "filterchecks.h"

#ifdef SIMULATE_DROP_MODE

#define FD_SAMPLING_RATIO 4

const uint16_t g_events_to_keep[] =
{
	PPME_SYSCALL_OPEN_E,
	PPME_SYSCALL_CLOSE_E,
	PPME_SYSCALL_READ_E,
	PPME_SYSCALL_WRITE_E,
	PPME_SYSCALL_EXECVE_E,
	PPME_CLONE_E,
	PPME_PROCEXIT_E,
	PPME_SOCKET_SOCKET_E,
	PPME_SOCKET_BIND_E,
	PPME_SOCKET_CONNECT_E,
	PPME_SOCKET_LISTEN_E,
	PPME_SOCKET_ACCEPT_E,
	PPME_SOCKET_SEND_E,
	PPME_SOCKET_SENDTO_E,
	PPME_SOCKET_RECV_E,
	PPME_SOCKET_RECVFROM_E,
	PPME_SOCKET_SHUTDOWN_E,
	PPME_SOCKET_GETSOCKNAME_E,
	PPME_SOCKET_GETPEERNAME_E,
	PPME_SOCKET_SOCKETPAIR_E,
	PPME_SOCKET_SETSOCKOPT_E,
	PPME_SOCKET_GETSOCKOPT_E,
	PPME_SOCKET_SENDMSG_E,
	PPME_SOCKET_SENDMMSG_E,
	PPME_SOCKET_RECVMSG_E,
	PPME_SOCKET_RECVMMSG_E,
	PPME_SOCKET_ACCEPT4_E,
	PPME_SYSCALL_CREAT_E,
	PPME_SYSCALL_PIPE_E,
	PPME_SYSCALL_EVENTFD_E,
	PPME_SYSCALL_FUTEX_E,
	PPME_SYSCALL_EPOLLWAIT_E,
	PPME_SYSCALL_POLL_E,
	PPME_SYSCALL_SELECT_E,
	PPME_SYSCALL_NEWSELECT_E,
	PPME_SYSCALL_IOCTL_E,
	PPME_SYSCALL_GETCWD_E,
	PPME_SYSCALL_CHDIR_E,
	PPME_SYSCALL_FCHDIR_E,
	PPME_SYSCALL_OPENAT_E,
	PPME_SYSCALL_PREAD_E,
	PPME_SYSCALL_PWRITE_E,
	PPME_SYSCALL_READV_E,
	PPME_SYSCALL_WRITEV_E,
	PPME_SYSCALL_PREADV_E,
	PPME_SYSCALL_PWRITEV_E,
	PPME_SYSCALL_DUP_E,
	PPME_SYSCALL_SIGNALFD_E,
	PPME_SYSCALL_TIMERFD_CREATE_E,
	PPME_SYSCALL_INOTIFY_INIT_E,
	PPME_SYSCALL_GETRLIMIT_E,
	PPME_SYSCALL_SETRLIMIT_E,
	PPME_SYSCALL_PRLIMIT_E,
	PPME_SCHEDSWITCH_E,
};

bool should_drop(sinsp_evt *evt)
{
	uint32_t j;
	bool res = true;
	uint64_t fd = 0;

	uint16_t etype = evt->get_type();
	uint16_t basetype = PPME_MAKE_ENTER(etype);

	for(j = 0; j < sizeof(g_events_to_keep) / sizeof(g_events_to_keep[0]); j++)
	{
		if(g_events_to_keep[j] == basetype)
		{
			res = false;
			break;
		}
	}

	ppm_event_flags eflags = evt->get_flags();

	if(eflags & (EF_DESTROYS_FD | EF_USES_FD))
	{
		if(PPME_IS_ENTER(etype))
		{
			//
			// The FD is always the first parameter
			//
			sinsp_evt_param *parinfo = evt->get_param(0);
			ASSERT(parinfo->m_len == sizeof(int64_t));
			fd = *(int32_t *)parinfo->m_val;
		}
		else
		{
			if(evt->get_thread_info())
			{
				fd = evt->get_thread_info()->m_lastevent_fd;
			}
			else
			{
				return true;
			}
		}
	}
	else
	{
		return res;
	}

	//
	// As a simple filter, we sample the events based on the
	// fds, hoping we will generate a better pattern instead
	// of just a random sampling
	//
	if(fd > 0 && (fd % FD_SAMPLING_RATIO))
	{
		return 1;
	}

	return res;
}

#endif