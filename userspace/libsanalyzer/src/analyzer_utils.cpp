#ifndef _WIN32
#include <unistd.h>
#include <sys/resource.h>
#include <dlfcn.h>
#ifndef CYGWING_AGENT
#include <execinfo.h>
#endif
#endif

#include <math.h>
#include "sinsp.h"
#include "sinsp_int.h"
#include "sinsp_errno.h"
#include "sinsp_signal.h"
#include "filter.h"
#include "filterchecks.h"
#include "analyzer_utils.h"
#include "setns.h"


#ifdef SIMULATE_DROP_MODE

#define FD_SAMPLING_RATIO 4
#define DROP_ID_NEVTS 10000

const uint16_t g_events_to_keep[] =
{
	PPME_SYSCALL_OPEN_E,
	PPME_SYSCALL_CLOSE_E,
	PPME_SYSCALL_READ_E,
	PPME_SYSCALL_WRITE_E,
	PPME_SYSCALL_EXECVE_E,
	PPME_CLONE_E,
	PPME_PROCEXIT_E,
	PPME_PROCEXIT_1_E,
	PPME_SOCKET_SOCKET_E,
	PPME_SOCKET_BIND_E,
	PPME_SOCKET_CONNECT_E,
	PPME_SOCKET_LISTEN_E,
	PPME_SOCKET_ACCEPT_E,
	PPME_SOCKET_ACCEPT_5_E,
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
	PPME_SOCKET_ACCEPT4_5_E,
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
	PPME_SCHEDSWITCHEX_E,
};

const uint16_t g_events_to_absolutely_keep[] =
{
	PPME_SYSCALL_OPEN_E,
	PPME_SYSCALL_CLOSE_E,
	PPME_SYSCALL_EXECVE_E,
	PPME_CLONE_E,
	PPME_PROCEXIT_E,
	PPME_PROCEXIT_1_E,
	PPME_SOCKET_CONNECT_E,
	PPME_SOCKET_ACCEPT_E,
	PPME_SOCKET_ACCEPT_5_E,
	PPME_SOCKET_SHUTDOWN_E,
	PPME_SOCKET_ACCEPT4_E,
	PPME_SOCKET_ACCEPT4_5_E,
	PPME_SYSCALL_CREAT_E,
	PPME_SYSCALL_PIPE_E,
	PPME_SYSCALL_EVENTFD_E,
	PPME_SYSCALL_FUTEX_E,
	PPME_SYSCALL_GETCWD_E,
	PPME_SYSCALL_CHDIR_E,
	PPME_SYSCALL_FCHDIR_E,
	PPME_SYSCALL_OPENAT_E,
	PPME_SYSCALL_DUP_E,
	PPME_SYSCALL_SIGNALFD_E,
	PPME_SYSCALL_TIMERFD_CREATE_E,
	PPME_SYSCALL_INOTIFY_INIT_E,
	PPME_SYSCALL_GETRLIMIT_E,
	PPME_SYSCALL_SETRLIMIT_E,
	PPME_SYSCALL_PRLIMIT_E,
};

uint32_t drop_id = 0;
uint32_t nevts = 0;

bool should_drop0(sinsp_evt *evt)
{
	uint32_t j;
	bool res = true;
	uint64_t fd = 0;

	evt->init();
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
		nevts++;

		if(nevts == DROP_ID_NEVTS)
		{
			drop_id++;

			if(drop_id == FD_SAMPLING_RATIO)
			{
				drop_id = 0;
			}

			nevts = 0;
		}

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
	if(fd > 3 && (fd % FD_SAMPLING_RATIO) != drop_id)
	{
		return true;
	}
	else
	{
		return false;
	}
}

uint32_t drop_group = 0;
bool is_dropping = false;
#define DROP_RATIO 2

bool should_drop(sinsp_evt *evt, bool* stopped, bool* switched)
{
	uint32_t j;
	bool must_keep = false;

	uint16_t etype = evt->get_type();
	uint16_t basetype = PPME_MAKE_ENTER(etype);

	for(j = 0; j < sizeof(g_events_to_absolutely_keep) / sizeof(g_events_to_absolutely_keep[0]); j++)
	{
		if(g_events_to_absolutely_keep[j] == basetype)
		{
			must_keep = true;
			break;
		}
	}

	bool old_dropping = is_dropping;
	*stopped = false;

	if(evt->get_ts() % ONE_SECOND_IN_NS <= ONE_SECOND_IN_NS / 2)
	{
		is_dropping = false;
	}
	else
	{
		is_dropping = true;
		*stopped = (old_dropping != is_dropping);
	}

	*switched = (old_dropping != is_dropping);

	if(evt->get_num() == 1)
	{
		*stopped = true;
	}

	if(must_keep == true)
	{
		return false;
	}
	else
	{
		return is_dropping;
	}
}

bool should_drop2(sinsp_evt *evt, bool* switched)
{
/*
	uint32_t j;
	drop_id++;
	*switched = false;

	uint16_t etype = evt->get_type();
	uint16_t basetype = PPME_MAKE_ENTER(etype);

	for(j = 0; j < sizeof(g_events_to_absolutely_keep) / sizeof(g_events_to_absolutely_keep[0]); j++)
	{
		if(g_events_to_absolutely_keep[j] == basetype)
		{
			return false;
		}
	}
*/
	if(drop_id >= 10000)
	{
		drop_group++;

		bool old_dropping = is_dropping;

		if(drop_group % DROP_RATIO == 0)
		{
			is_dropping = false;
		}
		else
		{
			is_dropping = true;
		}

		*switched = (old_dropping != is_dropping);
		drop_id = 0;
	}

	return is_dropping;
}

#endif /* SIMULATE_DROP_MODE */

// returns process rss in kb and cpu in [% * 100]
bool get_proc_mem_and_cpu(long& kb, int& cpu, std::string* err)
{
	static uint64_t prev_tot_time;
	static uint64_t prev_cpu_time;
	struct rusage usage;
	uint64_t now = sinsp_utils::get_current_time_ns();
	if(getrusage(RUSAGE_SELF, &usage) == -1)
	{
		if(err) { *err = strerror(errno); }
		return false;
	}
	uint64_t cpu_time = (usage.ru_utime.tv_sec + usage.ru_stime.tv_sec) * ONE_SECOND_IN_NS +
					(usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) * 1000;
	static int cpu_pct = -1;
	if(prev_tot_time)
	{
		uint64_t tot_diff = now - prev_tot_time;
		uint64_t tot_cpu = cpu_time - prev_cpu_time;
		if(tot_diff)
		{
			cpu_pct = (int)round((((double)tot_cpu / tot_diff) * 100./*%*/ * 100./*scale*/) / sysconf(_SC_NPROCESSORS_ONLN));
		}
	}
	prev_tot_time = now;
	prev_cpu_time = cpu_time;

	kb = usage.ru_maxrss;
	cpu = cpu_pct;
	return true;
}

void send_subprocess_heartbeat()
{
	struct rusage mem_usage;
	auto now = sinsp_utils::get_current_time_ns()/ONE_SECOND_IN_NS;
	getrusage(RUSAGE_SELF, &mem_usage);
	fprintf(stderr,"HB,%d,%ld,%llu\n", getpid(), mem_usage.ru_maxrss, now);
	fflush(stderr);
}

#ifndef CYGWING_AGENT
std::unordered_map<std::string, int> nsenter::m_home_ns;

nsenter::nsenter(int pid, const std::string& type):
	m_type(type)
{
	auto home_ns_it = m_home_ns.find(m_type);
	if(home_ns_it == m_home_ns.end())
	{
		auto fd = open_ns_fd(getpid(), m_type);
		if(fd <= 0)
		{
			throw sinsp_exception("Cannot open home namespace fd");
		}
		auto emplaced = m_home_ns.emplace(m_type, fd);
		home_ns_it = emplaced.first;
	}

	// Go to container ns
	auto fd = open_ns_fd(pid, m_type);
	if(fd <= 0)
	{
		throw sinsp_exception("Cannot open namespace fd for pid=" + std::to_string(pid));
	}
	auto ret = setns(fd, 0);
	close(fd);
	if(ret != 0)
	{
		throw sinsp_exception("Cannot setns to pid=" + std::to_string(pid));
	}
}

nsenter::~nsenter()
{
	if(setns(m_home_ns.at(m_type), 0) != 0)
	{
		g_logger.format(sinsp_logger::SEV_ERROR, "Cannot setns home");
		// Very bad error, better to crash at this point
		abort();
	}
}

int nsenter::open_ns_fd(int pid, const std::string& type)
{
	char filename[SCAP_MAX_PATH_SIZE];
	snprintf(filename, sizeof(filename), "%s/proc/%d/ns/%s", scap_get_host_root(), pid, type.c_str());
	return open(filename, O_RDONLY);
}
#endif // CYGWING_AGENT


template<>
void threshold_filter<double>::log(double value)
{
	g_logger.format(sinsp_logger::SEV_WARNING, "%s above threshold curr=%.2f/%.2f %u:%u", m_desc, value, m_threshold, m_ntimes, m_ntimes_max);
}

template<>
void threshold_filter<long>::log(long value)
{
	g_logger.format(sinsp_logger::SEV_WARNING, "%s above threshold curr=%ld/%ld %u:%u", m_desc, value, m_threshold, m_ntimes, m_ntimes_max);
}

#ifndef _WIN32
#ifndef CYGWING_AGENT
thread_local void *exception_backtrace[1024];
thread_local int exception_backtrace_size;
extern "C" {
	void __cxa_throw(void *ex, void *info, void (*dest)(void *))
	{
		static void (*const __throw_exc)(void*,void*,void(*)(void*)) __attribute__ ((noreturn)) = (void (*)(void*,void*,void(*)(void*)))dlsym(RTLD_NEXT, "__cxa_throw");

		exception_backtrace_size = backtrace(exception_backtrace, 1024);

		if(!__throw_exc) {
			g_logger.format(sinsp_logger::SEV_ERROR, "Unable to rethrow exception");
			ASSERT(false);
		}
		__throw_exc(ex,info,dest);
	}
}
#endif
#endif
