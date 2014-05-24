#include <termios.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <poll.h>

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

	//
	// TEST CODE
	//
	run_callback_t test = [](sinsp* inspector)
	{
		int fd, status;

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

		if(type == PPME_SYSCALL_IOCTL_E)
		{
			EXPECT_EQ("<f>/dev/ttyS0", e->get_param_value_str("fd"));
			EXPECT_EQ(NumberFormatter::formatHex(TIOCMGET), e->get_param_value_str("request"));
			callnum++;
		}
		else if(type == PPME_SYSCALL_IOCTL_X)
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

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_BRK_4_E)
		{
			callnum++;
		}
		else if(type == PPME_SYSCALL_BRK_4_X)
		{

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

				EXPECT_GT(after_brk_vmsize, before_brk_vmsize);
				EXPECT_GE(after_brk_vmrss, before_brk_vmrss);
			}

			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	EXPECT_EQ(4, callnum);
}
