#include <termios.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <sys/mman.h>

#include "sys_call_test.h"
#include <gtest.h>
#include <algorithm>
#include "event_capture.h"
#include <sys/stat.h>
#include <Poco/Process.h>
#include <Poco/PipeStream.h>
#include <list>
#include <cassert>
#include <event.h>
#include <Poco/StringTokenizer.h>
#include <Poco/NumberFormatter.h>
#include <Poco/NumberParser.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/quota.h>
#include <unistd.h>

using namespace std;

using Poco::StringTokenizer;
using Poco::NumberFormatter;
using Poco::NumberParser;

uint32_t get_server_address()
{
	struct ifaddrs *interfaceArray = NULL;
	struct ifaddrs *tempIfAddr = NULL;
	int rc = 0;
	uint32_t address = 0;

	rc = getifaddrs(&interfaceArray);
	if(rc != 0)
	{
		return -1;
	}
	for(tempIfAddr = interfaceArray; tempIfAddr != NULL; tempIfAddr = tempIfAddr->ifa_next)
	{
		if(tempIfAddr->ifa_addr == NULL)
		{
			// "eql" interface like on EC2
			continue;
		}

		if(tempIfAddr->ifa_addr->sa_family != AF_INET)
		{
			continue;
		}
		
		if(0 == strcmp("lo",tempIfAddr->ifa_name))
		{
			continue;
		}
		address = *(uint32_t*)&((struct sockaddr_in *)tempIfAddr->ifa_addr)->sin_addr;
		break;
	}
	freeifaddrs(interfaceArray);

	return address;
}

uint32_t parse_ipv4_addr(const char *dotted_notation)
{
	uint32_t a, b, c, d;
	sscanf(dotted_notation, "%d.%d.%d.%d", &a, &b, &c, &d);
	return d << 24 | c << 16 | b << 8 | a;
}

bool ends_with(std::string const &s, std::string const &ending)
{
	if(s.length() >= ending.length())
	{
		return (0 == s.compare(s.length() - ending.length(), ending.length(), ending));
	}
	else
	{
		return false;
	}
}

void wait_for_process_start(Poco::Pipe &pipe)
{
	Poco::PipeInputStream istr(pipe);
	std::string s;
	while(s != "STARTED")
	{
		s += (char) istr.get();
	}
}

void wait_for_all(process_handles_t &handles)
{
	for(process_handles_t::iterator it = handles.begin(); it != handles.end(); it++)
	{
		it->wait();
	}
}

tuple<Poco::ProcessHandle,Poco::Pipe*> start_process(proc* process)
{
	Poco::Pipe* pipe = new Poco::Pipe();
	Poco::ProcessHandle handle = Poco::Process::launch(process->get_command(), process->get_arguments(), 0, pipe, 0);
	wait_for_process_start(*pipe);
	return make_tuple(handle,pipe);
}

void run_processes(process_list_t &processes)
{
	process_handles_t handles;
	list<Poco::Pipe> pipes;
	for(process_list_t::iterator it = processes.begin(); it != processes.end(); it++)
	{
		Poco::Pipe pipe;
		pipes.push_back(pipe);
		Poco::ProcessHandle handle = Poco::Process::launch(it->get_command(), it->get_arguments(), 0, &pipe, 0);
		wait_for_process_start(pipe);
		handles.push_back(handle);
	}
	wait_for_all(handles);
}

TEST_F(sys_call_test, stat)
{
	int callnum = 0;
	event_filter_t filter = [&](sinsp_evt * evt)
	{
#ifdef __i386__
		return 0 == strcmp(evt->get_name(), "stat64") && m_tid_filter(evt);
#else
		return 0 == strcmp(evt->get_name(), "stat") && m_tid_filter(evt);
#endif
	};
	run_callback_t test = [](sinsp* inspector)
	{
		struct stat sb;
		stat("/tmp", &sb);
	};
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		callnum++;
	};
	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	EXPECT_EQ(2, callnum);
}

TEST_F(sys_call_test, open_close)
{
	int callnum = 0;
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return (0 == strcmp(evt->get_name(), "open") || 0 == strcmp(evt->get_name(), "close")) && m_tid_filter(evt);
	};
	run_callback_t test = [](sinsp* inspector)
	{
		int fd = open("/tmp", O_RDONLY);
		close(fd);
	};
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		if (0 == strcmp(param.m_evt->get_name(),"open") && param.m_evt->get_direction() == SCAP_ED_OUT)
		{
			EXPECT_EQ("<f>/tmp", param.m_evt->get_param_value_str("fd"));
		}
		callnum++;
	};
	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	EXPECT_EQ(4, callnum);
}

TEST_F(sys_call_test, poll_timeout)
{
	int callnum = 0;
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return !strcmp(evt->get_name(), "poll") && m_tid_filter(evt);
	};
	run_callback_t test = [](sinsp* inspector)
	{
		struct pollfd ufds[2];
		ufds[0].fd = 0;
		ufds[0].events = POLLIN;
		ufds[1].fd = 1;
		ufds[1].events = POLLOUT;
		poll(ufds, 2, 20);
	};
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_POLL_E)
		{
			//
			// stdin and stdout can be a file or a fifo depending
			// on how the tests are invoked
			//
			string fds = e->get_param_value_str("fds");
			EXPECT_TRUE(fds == "0:f1 1:f4" || fds == "0:p1 1:p4");
			EXPECT_EQ("20", e->get_param_value_str("timeout"));
			callnum++;
		}
		else if(type == PPME_SYSCALL_POLL_X)
		{
			int64_t res = NumberParser::parse(e->get_param_value_str("res"));
			
			EXPECT_GT(res, 0);
			EXPECT_LE(res, 2);

			string fds = e->get_param_value_str("fds");

			switch(res)
			{
				case 1:
					EXPECT_TRUE(fds == "1:f4" || fds == "1:p4");
					break;
				case 2:
					//
					// On EC2 called from jenkins stdin returns POLLHUP
					//
					EXPECT_TRUE(fds == "0:f1 1:f4" || fds == "0:p21 1:p4" || fds == "0:p20 1:p4");
					break;
				default:
					FAIL();
			}

			callnum++;
		}
	};
	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	EXPECT_EQ(2, callnum);
}

const char *param_value_str(sinsp_evt *evt, uint32_t param_index)
{
	const char *param_value;
	return evt->get_param_as_str(param_index, &param_value);
}

TEST(inspector, invalid_file_name)
{
	sinsp inspector;
	ASSERT_THROW(inspector.open("invalid_file_name"), sinsp_exception);
}

TEST_F(sys_call_test, ioctl)
{
	int callnum = 0;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return m_tid_filter(evt);
	};

	int status;

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		int fd;

		fd = open("/dev/ttyS0", O_RDONLY);
		ioctl(fd, TIOCMGET, &status);
		close(fd);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_IOCTL_3_E)
		{
			EXPECT_EQ("<f>/dev/ttyS0", e->get_param_value_str("fd"));
			EXPECT_EQ(NumberFormatter::formatHex(TIOCMGET), e->get_param_value_str("request"));
			EXPECT_EQ(NumberFormatter::formatHex((unsigned long) &status), e->get_param_value_str("argument"));
			callnum++;
		}
		else if(type == PPME_SYSCALL_IOCTL_3_X)
		{
			string res = e->get_param_value_str("res");
			EXPECT_TRUE(res == "0" || res == "EIO");
			callnum++;
		}
	};
	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
}

TEST_F(sys_call_test, shutdown)
{
	int callnum = 0;
	int sock;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return m_tid_filter(evt);
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		if((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		{
			FAIL() << "socket() failed";
			return;
		}

		shutdown(sock, SHUT_RD);
		shutdown(sock, SHUT_WR);
		shutdown(sock, SHUT_RDWR);

		close(sock);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SOCKET_SHUTDOWN_E)
		{
			EXPECT_EQ(NumberFormatter::format(sock), e->get_param_value_str("fd", false));
			
			if(callnum == 0)
			{
				EXPECT_EQ("0", e->get_param_value_str("how", false));
			}
			else if(callnum == 2)
			{
				EXPECT_EQ("1", e->get_param_value_str("how", false));
			}
			else if(callnum == 4)
			{
				EXPECT_EQ("2", e->get_param_value_str("how", false));
			}

			callnum++;
		}
		else if(type == PPME_SOCKET_SHUTDOWN_X)
		{
			EXPECT_GT(0, NumberParser::parse(e->get_param_value_str("res", false)));
			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

	EXPECT_EQ(6, callnum);
}

TEST_F(sys_call_test, timerfd)
{
	int callnum = 0;
	int fd;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return m_tid_filter(evt);
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		int ret;
		unsigned int ns;
		unsigned int sec;
		struct itimerspec itval;
		unsigned int period = 100000;
		unsigned long long missed;

		/* Create the timer */
		fd = timerfd_create (CLOCK_MONOTONIC, 0);
		if (fd == -1)
		{
			FAIL();
		}

		/* Make the timer periodic */
		sec = period/1000000;
		ns = (period - (sec * 1000000)) * 1000;
		itval.it_interval.tv_sec = sec;
		itval.it_interval.tv_nsec = ns;
		itval.it_value.tv_sec = sec;
		itval.it_value.tv_nsec = ns;
		ret = timerfd_settime (fd, 0, &itval, NULL);

		/* Wait for the next timer event. If we have missed any the
		   number is written to "missed" */
		ret = read (fd, &missed, sizeof (missed));
		if (ret == -1)
		{
			FAIL();
		}

		close(fd);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_TIMERFD_CREATE_E)
		{
			EXPECT_EQ(0, NumberParser::parse(e->get_param_value_str("clockid")));
			EXPECT_EQ(0, NumberParser::parse(e->get_param_value_str("flags")));
			callnum++;
		}
		else if(type == PPME_SYSCALL_TIMERFD_CREATE_X)
		{
			EXPECT_EQ(fd, NumberParser::parse(e->get_param_value_str("res", false)));
			callnum++;
		}
		else if(type == PPME_SYSCALL_READ_E)
		{
			if(callnum == 2)
			{
				EXPECT_EQ("<t>", e->get_param_value_str("fd"));
				EXPECT_EQ(fd, NumberParser::parse(e->get_param_value_str("fd", false)));
				callnum++;
			}
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

	EXPECT_EQ(3, callnum);
}

TEST_F(sys_call_test, timestamp)
{
	static const uint64_t TIMESTAMP_DELTA_NS = 1000000; // We should at least always have 1 ms resolution
	uint64_t timestampv[20];
	int callnum = 0;

	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return m_tid_filter(evt);
	};

	run_callback_t test = [&](sinsp* inspector)
	{
		useconds_t sleep_period = 10;
		struct timeval tv;
		for(uint32_t j = 0; j < sizeof(timestampv) / sizeof(timestampv[0]); ++j)
		{
			syscall(SYS_gettimeofday, &tv, NULL);
			timestampv[j] = tv.tv_sec * 1000000000LL + tv.tv_usec * 1000;
			usleep(sleep_period);
			sleep_period *= 2;
		}
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		if(param.m_evt->get_type() == PPME_GENERIC_X && param.m_evt->get_param_value_str("ID") == "gettimeofday")
		{
			EXPECT_LE(param.m_evt->get_ts(), timestampv[callnum] + TIMESTAMP_DELTA_NS);
			EXPECT_GE(param.m_evt->get_ts(), timestampv[callnum] - TIMESTAMP_DELTA_NS);
			++callnum;
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	EXPECT_EQ((int) (sizeof(timestampv) / sizeof(timestampv[0])), callnum);
}

TEST_F(sys_call_test, brk)
{
	int callnum = 0;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return m_tid_filter(evt);
	};

	//
	// TEST CODE
	//
	run_callback_t test = [](sinsp* inspector)
	{
		sbrk(1000);
		sbrk(100000);
	};

	uint32_t before_brk_vmsize;
	uint32_t before_brk_vmrss;
	uint32_t after_brk_vmsize;
	uint32_t after_brk_vmrss;
	bool ignore_this_call = false;

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_BRK_4_E)
		{
			uint64_t addr = *((uint64_t*) e->get_param_value_raw("addr")->m_val);
			if(addr == 0)
			{
				ignore_this_call = true;
				return;
			}

			callnum++;
		}
		else if(type == PPME_SYSCALL_BRK_4_X)
		{
			if(ignore_this_call)
			{
				ignore_this_call = false;
				return;
			}

			uint32_t vmsize = *((uint32_t*) e->get_param_value_raw("vm_size")->m_val);
			uint32_t vmrss = *((uint32_t*) e->get_param_value_raw("vm_rss")->m_val);

			EXPECT_EQ(e->get_thread_info(false)->m_vmsize_kb, vmsize);
			EXPECT_EQ(e->get_thread_info(false)->m_vmrss_kb, vmrss);

			if(callnum == 1)
			{
				before_brk_vmsize = vmsize;
				before_brk_vmrss = vmrss;
			}
			else if(callnum == 3)
			{
				after_brk_vmsize = vmsize;
				after_brk_vmrss = vmrss;

				EXPECT_GT(after_brk_vmsize, before_brk_vmsize + 50);
				EXPECT_GE(after_brk_vmrss, before_brk_vmrss);
			}

			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	EXPECT_EQ(4, callnum);
}

TEST_F(sys_call_test, mmap)
{
	int callnum = 0;
	int errno2;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return m_tid_filter(evt);
	};

	void* p;

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		munmap((void*) 0x50, 300);
		p = mmap(0, 0, PROT_EXEC|PROT_READ|PROT_WRITE, MAP_SHARED|MAP_PRIVATE|MAP_ANONYMOUS|MAP_DENYWRITE, -1, 0);
		EXPECT_EQ((uint64_t) -1, (uint64_t) p);
		errno2 = errno;
		p = mmap(NULL, 1003520, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
		EXPECT_NE((uint64_t) 0, (uint64_t) p);
		munmap(p, 1003520);
	};

	uint32_t enter_vmsize;
	uint32_t enter_vmrss;
	uint32_t exit_vmsize;
	uint32_t exit_vmrss;

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_MUNMAP_E)
		{
			callnum++;

			enter_vmsize = e->get_thread_info(false)->m_vmsize_kb;
			enter_vmrss = e->get_thread_info(false)->m_vmrss_kb;

			switch(callnum)
			{
			case 1:
				EXPECT_EQ("50", e->get_param_value_str("addr"));
				EXPECT_EQ("300", e->get_param_value_str("length"));
				break;
			case 7:
			{
				uint64_t addr = *((uint64_t*) e->get_param_value_raw("addr")->m_val);
#ifdef __LP64__
				EXPECT_EQ((uint64_t) p, addr);
#else
				EXPECT_EQ(((uint32_t) p), addr);
#endif				
				EXPECT_EQ("1003520", e->get_param_value_str("length"));
				break;
			}
			default:
				EXPECT_TRUE(false);
			}
		}
		else if(type == PPME_SYSCALL_MUNMAP_X)
		{
			callnum++;

			exit_vmsize = *((uint32_t*) e->get_param_value_raw("vm_size")->m_val);
			exit_vmrss = *((uint32_t*) e->get_param_value_raw("vm_rss")->m_val);
			EXPECT_EQ(e->get_thread_info(false)->m_vmsize_kb, exit_vmsize);
			EXPECT_EQ(e->get_thread_info(false)->m_vmrss_kb, exit_vmrss);

			switch(callnum)
			{
			case 2:
				EXPECT_EQ("EINVAL", e->get_param_value_str("res"));
				EXPECT_EQ("-22", e->get_param_value_str("res", false));
				break;
			case 8:
				EXPECT_EQ("0", e->get_param_value_str("res"));
				EXPECT_GT(enter_vmsize, exit_vmsize + 500);
				EXPECT_GE(enter_vmrss, enter_vmrss);
				break;
			default:
				EXPECT_TRUE(false);
			}
		}
		else if(type == PPME_SYSCALL_MMAP_E || type == PPME_SYSCALL_MMAP2_E)
		{
			callnum++;

			enter_vmsize = e->get_thread_info(false)->m_vmsize_kb;
			enter_vmrss = e->get_thread_info(false)->m_vmrss_kb;

			switch(callnum)
			{
			case 3:
				EXPECT_EQ("0", e->get_param_value_str("addr"));
				EXPECT_EQ("0", e->get_param_value_str("length"));
				EXPECT_EQ("PROT_READ|PROT_WRITE|PROT_EXEC", e->get_param_value_str("prot"));
				EXPECT_EQ("MAP_SHARED|MAP_PRIVATE|MAP_ANONYMOUS|MAP_DENYWRITE", e->get_param_value_str("flags"));
#ifdef __LP64__
				EXPECT_EQ("4294967295", e->get_param_value_str("fd", false));
#else
				EXPECT_EQ("-1", e->get_param_value_str("fd", false));
#endif
				if(type == PPME_SYSCALL_MMAP_E)
				{
					EXPECT_EQ("0", e->get_param_value_str("offset"));
				}
				else
				{
					EXPECT_EQ("0", e->get_param_value_str("pgoffset"));					
				}
				break;
			case 5:
				EXPECT_EQ("0", e->get_param_value_str("addr"));
				EXPECT_EQ("1003520", e->get_param_value_str("length"));
				EXPECT_EQ("PROT_READ|PROT_WRITE", e->get_param_value_str("prot"));
				EXPECT_EQ("MAP_PRIVATE|MAP_ANONYMOUS", e->get_param_value_str("flags"));
#ifdef __LP64__
				EXPECT_EQ("4294967295", e->get_param_value_str("fd", false));
#else
				EXPECT_EQ("-1", e->get_param_value_str("fd", false));
#endif
				if(type == PPME_SYSCALL_MMAP_E)
				{
					EXPECT_EQ("0", e->get_param_value_str("offset"));
				}
				else
				{
					EXPECT_EQ("0", e->get_param_value_str("pgoffset"));					
				}
				break;
			default:
				EXPECT_TRUE(false);
			}
		}
		else if(type == PPME_SYSCALL_MMAP_X || type == PPME_SYSCALL_MMAP2_X)
		{
			callnum++;

			exit_vmsize = *((uint32_t*) e->get_param_value_raw("vm_size")->m_val);
			exit_vmrss = *((uint32_t*) e->get_param_value_raw("vm_rss")->m_val);
			EXPECT_EQ(e->get_thread_info(false)->m_vmsize_kb, exit_vmsize);
			EXPECT_EQ(e->get_thread_info(false)->m_vmrss_kb, exit_vmrss);

			switch(callnum)
			{
			case 4:
			{
				uint64_t res = *((uint64_t*) e->get_param_value_raw("res")->m_val);
				EXPECT_EQ(-errno2, (int64_t) res);
				break;
			}
			case 6:
			{
				uint64_t res = *((uint64_t*) e->get_param_value_raw("res")->m_val);
				EXPECT_EQ((uint64_t) p, res);
				EXPECT_GT(exit_vmsize, enter_vmsize + 500);
				EXPECT_GE(exit_vmrss, enter_vmrss);
				break;
			}
			default:
				EXPECT_TRUE(false);
			}
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	EXPECT_EQ(8, callnum);
}

TEST_F(sys_call_test, quotactl_ko)
{
	int callnum = 0;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return m_tid_filter(evt);
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		quotactl(QCMD(Q_QUOTAON, USRQUOTA), "/dev/xxx", 2, "/quota.user"); // 2 => QFMT_VFS_V0
		quotactl(QCMD(Q_QUOTAOFF, GRPQUOTA), "/dev/xxx", 0, NULL);
	};

	//
	// OUTPUT VALIDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();
		if (type == PPME_SYSCALL_QUOTACTL_E)
		{
			++callnum;
			switch(callnum)
			{
			case 1:
				EXPECT_EQ("Q_QUOTAON", e->get_param_value_str("cmd"));
				EXPECT_EQ("USRQUOTA", e->get_param_value_str("type"));
				EXPECT_EQ("QFMT_VFS_V0", e->get_param_value_str("quota_fmt"));
				break;
			case 3:
				EXPECT_EQ("Q_QUOTAOFF", e->get_param_value_str("cmd"));
				EXPECT_EQ("GRPQUOTA", e->get_param_value_str("type"));
			}
		}
		else if ( type == PPME_SYSCALL_QUOTACTL_X)
		{
			++callnum;
			switch(callnum)
			{
			case 2:
				EXPECT_EQ("-2", e->get_param_value_str("res", false));
				EXPECT_EQ("/dev/xxx", e->get_param_value_str("special"));
				EXPECT_EQ("/quota.user", e->get_param_value_str("quotafilepath"));
				break;
			case 4:
				EXPECT_EQ("-2", e->get_param_value_str("res", false));
				EXPECT_EQ("/dev/xxx", e->get_param_value_str("special"));
			}
		}
	};
	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	EXPECT_EQ(4, callnum);
}

TEST_F(sys_call_test, quotactl_ok)
{
	int callnum = 0;

	// Clean environment
	system("umount /tmp/testquotamnt");
	system("rm -r /tmp/testquotactl /tmp/testquotamnt");
	// Setup a tmpdisk to test quotas
	char command[] = "dd if=/dev/zero of=/tmp/testquotactl bs=1M count=200 &&\n"
						"echo y | mkfs.ext4 -q /tmp/testquotactl &&\n"
						"mkdir -p /tmp/testquotamnt &&\n"
						"mount -o usrquota,grpquota,loop=/dev/loop0 /tmp/testquotactl /tmp/testquotamnt &&\n"
						"quotacheck -cug /tmp/testquotamnt";
	int ret = system(command);
	if (ret != 0)
	{
		// If we don't have quota utilities, skip this test
		return;
	}
	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return m_tid_filter(evt);
	};

	//
	// TEST CODE
	//
	struct dqblk mydqblk;
	struct dqinfo mydqinfo;
	run_callback_t test = [&](sinsp* inspector)
	{
		quotactl(QCMD(Q_QUOTAON, USRQUOTA), "/dev/loop0", 2, "/tmp/testquotamnt/aquota.user"); // 2 => QFMT_VFS_V0
		quotactl(QCMD(Q_GETQUOTA, USRQUOTA), "/dev/loop0", 0, (caddr_t)&mydqblk); // 0 => root user
		quotactl(QCMD(Q_GETINFO, USRQUOTA), "/dev/loop0", 0, (caddr_t)&mydqinfo);
		quotactl(QCMD(Q_QUOTAOFF, USRQUOTA), "/dev/loop0", 0, NULL);
	};

	//
	// OUTPUT VALIDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();
		if (type == PPME_SYSCALL_QUOTACTL_E)
		{
			++callnum;
			switch(callnum)
			{
			case 1:
				EXPECT_EQ("Q_QUOTAON", e->get_param_value_str("cmd"));
				EXPECT_EQ("USRQUOTA", e->get_param_value_str("type"));
				EXPECT_EQ("QFMT_VFS_V0", e->get_param_value_str("quota_fmt"));
				break;
			case 3:
				EXPECT_EQ("Q_GETQUOTA", e->get_param_value_str("cmd"));
				EXPECT_EQ("USRQUOTA", e->get_param_value_str("type"));
				EXPECT_EQ("0", e->get_param_value_str("id"));
				break;
			case 5:
				EXPECT_EQ("Q_GETINFO", e->get_param_value_str("cmd"));
				EXPECT_EQ("USRQUOTA", e->get_param_value_str("type"));
				break;
			case 7:
				EXPECT_EQ("Q_QUOTAOFF", e->get_param_value_str("cmd"));
				EXPECT_EQ("USRQUOTA", e->get_param_value_str("type"));
				break;
			}
		}
		else if ( type == PPME_SYSCALL_QUOTACTL_X)
		{
			++callnum;
			switch(callnum)
			{
			case 2:
				EXPECT_EQ("0", e->get_param_value_str("res", false));
				EXPECT_EQ("/dev/loop0", e->get_param_value_str("special"));
				EXPECT_EQ("/tmp/testquotamnt/aquota.user", e->get_param_value_str("quotafilepath"));
				break;
			case 4:
				EXPECT_EQ("0", e->get_param_value_str("res", false));
				EXPECT_EQ("/dev/loop0", e->get_param_value_str("special"));
				EXPECT_EQ(mydqblk.dqb_bhardlimit, *reinterpret_cast<uint64_t*>(e->get_param_value_raw("dqb_bhardlimit")->m_val));
				EXPECT_EQ(mydqblk.dqb_bsoftlimit, *reinterpret_cast<uint64_t*>(e->get_param_value_raw("dqb_bsoftlimit")->m_val));
				EXPECT_EQ(mydqblk.dqb_curspace, *reinterpret_cast<uint64_t*>(e->get_param_value_raw("dqb_curspace")->m_val));
				EXPECT_EQ(mydqblk.dqb_ihardlimit, *reinterpret_cast<uint64_t*>(e->get_param_value_raw("dqb_ihardlimit")->m_val));
				EXPECT_EQ(mydqblk.dqb_isoftlimit, *reinterpret_cast<uint64_t*>(e->get_param_value_raw("dqb_isoftlimit")->m_val));
				EXPECT_EQ(mydqblk.dqb_btime, *reinterpret_cast<uint64_t*>(e->get_param_value_raw("dqb_btime")->m_val));
				EXPECT_EQ(mydqblk.dqb_itime, *reinterpret_cast<uint64_t*>(e->get_param_value_raw("dqb_itime")->m_val));
				break;
			case 6:
				EXPECT_EQ("0", e->get_param_value_str("res", false));
				EXPECT_EQ("/dev/loop0", e->get_param_value_str("special"));
				EXPECT_EQ(mydqinfo.dqi_bgrace, *reinterpret_cast<uint64_t*>(e->get_param_value_raw("dqi_bgrace")->m_val));
				EXPECT_EQ(mydqinfo.dqi_igrace, *reinterpret_cast<uint64_t*>(e->get_param_value_raw("dqi_igrace")->m_val));
				break;
			case 8:
				EXPECT_EQ("0", e->get_param_value_str("res", false));
				EXPECT_EQ("/dev/loop0", e->get_param_value_str("special"));
				break;
			}
		}
	};
	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	EXPECT_EQ(8, callnum);
}

TEST_F(sys_call_test, setresuid_and_gid)
{
	static const uint32_t test_uid = 5454;
	static const uint32_t test_gid = 6565;
	int callnum = 0;

	// Clean environment
	system("userdel testsetresuid");
	system("groupdel testsetresgid");
	// Setup a tmpdisk to test quotas
	char command[] = "useradd -u 5454 testsetresuid &&\n"
						"groupadd -g 6565 testsetresgid";
	int ret = system(command);
	ASSERT_EQ(0, ret);
	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return m_tid_filter(evt);
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		setresuid(test_uid, -1, -1);
		setresgid(test_gid, -1, -1);
	};

	//
	// OUTPUT VALIDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();
		if (type == PPME_SYSCALL_SETRESUID_E)
		{
			++callnum;
			EXPECT_EQ("5454", e->get_param_value_str("ruid", false));
			EXPECT_EQ("testsetresuid", e->get_param_value_str("ruid"));
			EXPECT_EQ("-1", e->get_param_value_str("euid", false));
			EXPECT_EQ("<NONE>", e->get_param_value_str("euid"));
			EXPECT_EQ("-1", e->get_param_value_str("suid", false));
			EXPECT_EQ("<NONE>", e->get_param_value_str("suid"));
		}
		else if ( type == PPME_SYSCALL_SETRESUID_X)
		{
			++callnum;
			EXPECT_EQ("0", e->get_param_value_str("res", false));
		} else if ( type == PPME_SYSCALL_SETRESGID_E)
		{
			++callnum;
			EXPECT_EQ("6565", e->get_param_value_str("rgid", false));
			EXPECT_EQ("testsetresgid", e->get_param_value_str("rgid"));
			EXPECT_EQ("-1", e->get_param_value_str("egid", false));
			EXPECT_EQ("<NONE>", e->get_param_value_str("egid"));
			EXPECT_EQ("-1", e->get_param_value_str("sgid", false));
			EXPECT_EQ("<NONE>", e->get_param_value_str("sgid"));
		} else if ( type == PPME_SYSCALL_SETRESGID_X)
		{
			++callnum;
			EXPECT_EQ("0", e->get_param_value_str("res", false));
		}
	};
	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	EXPECT_EQ(4, callnum);
}

TEST_F(sys_call_test, setuid_and_gid)
{
	static const uint32_t test_gid = 6565;
	int callnum = 0;

	// Clean environment
	system("groupdel testsetresgid");
	// Setup a tmpdisk to test quotas
	char command[] = "groupadd -g 6565 testsetresgid";
	int ret = system(command);
	ASSERT_EQ(0, ret);
	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return m_tid_filter(evt);
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		// TODO: To set setuid we need to fork the process
		setgid(test_gid);
	};

	//
	// OUTPUT VALIDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();
		if (type == PPME_SYSCALL_SETUID_E)
		{
			++callnum;
			EXPECT_EQ("9090", e->get_param_value_str("uid", false));
		}
		else if ( type == PPME_SYSCALL_SETUID_X)
		{
			++callnum;
			EXPECT_EQ("0", e->get_param_value_str("res", false));
		} else if ( type == PPME_SYSCALL_SETGID_E)
		{
			++callnum;
			EXPECT_EQ("6565", e->get_param_value_str("gid", false));
			EXPECT_EQ("testsetresgid", e->get_param_value_str("gid"));
		} else if ( type == PPME_SYSCALL_SETGID_X)
		{
			++callnum;

			EXPECT_EQ("0", e->get_param_value_str("res", false));
		}
	};
	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	EXPECT_EQ(2, callnum);
}
