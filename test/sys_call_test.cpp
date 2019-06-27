#include <termios.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <sys/mman.h>
#include <numeric>

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

#include "setns.h"
#include "scap-int.h"

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

void wait_for_message(Poco::Pipe &pipe, const char *msg)
{
	int mlen = strlen(msg);
	char buf[mlen+1];
	int readlen, nr;

	for (readlen = nr = 0; readlen < mlen; readlen += nr)
	{
		nr = pipe.readBytes(buf+readlen, mlen-readlen);
		if (nr < 1)
			break;
	}

	if (readlen != mlen)
	{
		FAIL() << "Cannot read message, read=" << readlen;
	}
	ASSERT_EQ(0, strncmp((const char*)buf, msg, mlen)) << "Error waiting for message " << msg;
}

void wait_for_process_start(Poco::Pipe &pipe)
{
	wait_for_message(pipe, "STARTED\n");
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
	auto child_proc = start_process_sync(process);
	delete get<1>(child_proc);
	return make_tuple(get<0>(child_proc), get<2>(child_proc));
}

tuple<Poco::ProcessHandle,Poco::Pipe*,Poco::Pipe*> start_process_sync(proc* process)
{
	Poco::Pipe* stdin_pipe = new Poco::Pipe();
	Poco::Pipe* stdout_pipe = new Poco::Pipe();
	Poco::ProcessHandle handle = Poco::Process::launch(process->get_command(), process->get_arguments(), stdin_pipe, stdout_pipe, 0);
	wait_for_process_start(*stdout_pipe);
	return make_tuple(handle,stdin_pipe,stdout_pipe);
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
		return (0 == strcmp(evt->get_name(), "open") ||
		        0 == strcmp(evt->get_name(), "openat") ||
		        0 == strcmp(evt->get_name(), "close")
			) && m_tid_filter(evt);
	};
	run_callback_t test = [](sinsp* inspector)
	{
		int fd = open("/tmp", O_RDONLY);
		close(fd);
	};
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		if ((0 == strcmp(param.m_evt->get_name(),"open") ||
		     0 == strcmp(param.m_evt->get_name(), "openat")) &&
		   param.m_evt->get_direction() == SCAP_ED_OUT)
		{
			EXPECT_EQ("<f>/tmp", param.m_evt->get_param_value_str("fd"));
		}
		callnum++;
	};
	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	EXPECT_EQ(4, callnum);
}

TEST_F(sys_call_test, open_close_dropping)
{
	int callnum = 0;
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return (0 == strcmp(evt->get_name(), "open") ||
		        0 == strcmp(evt->get_name(), "openat") ||
		        0 == strcmp(evt->get_name(), "close")
			) && m_tid_filter(evt);
	};
	run_callback_t test = [](sinsp* inspector)
	{
		inspector->start_dropping_mode(1);
		int fd = open("/tmp", O_RDONLY);
		close(fd);
		inspector->stop_dropping_mode();
	};
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		if ((0 == strcmp(param.m_evt->get_name(),"open") ||
		     0 == strcmp(param.m_evt->get_name(), "openat")) &&
		   param.m_evt->get_direction() == SCAP_ED_OUT)
		{
			EXPECT_EQ("<f>/tmp", param.m_evt->get_param_value_str("fd"));
		}
		callnum++;
	};
	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	EXPECT_EQ(4, callnum);
}

TEST_F(sys_call_test, fcntl_getfd)
{
	int callnum = 0;
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return 0 == strcmp(evt->get_name(), "fcntl") && m_tid_filter(evt);
	};
	run_callback_t test = [](sinsp* inspector)
	{
		fcntl(0, F_GETFL);
	};
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		callnum++;
	};
	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	EXPECT_EQ(2, callnum);
}

TEST_F(sys_call_test, fcntl_getfd_dropping)
{
	int callnum = 0;
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return 0 == strcmp(evt->get_name(), "fcntl") && m_tid_filter(evt);
	};
	run_callback_t test = [](sinsp* inspector)
	{
		inspector->start_dropping_mode(1);
		fcntl(0, F_GETFL);
		inspector->stop_dropping_mode();
	};
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		callnum++;
	};
	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	EXPECT_EQ(0, callnum);
}

TEST_F(sys_call_test, bind_error)
{
	int callnum = 0;
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return 0 == strcmp(evt->get_name(), "bind") && m_tid_filter(evt);
	};
	run_callback_t test = [](sinsp* inspector)
	{
		bind(0, NULL, 0);
	};
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		callnum++;
	};
	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	EXPECT_EQ(2, callnum);
}

TEST_F(sys_call_test, bind_error_dropping)
{
	int callnum = 0;
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return 0 == strcmp(evt->get_name(), "bind") && m_tid_filter(evt);
	};
	run_callback_t test = [](sinsp* inspector)
	{
		inspector->start_dropping_mode(1);
		bind(0, NULL, 0);
		inspector->stop_dropping_mode();
	};
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		callnum++;
	};
	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	EXPECT_EQ(1, callnum);
}

TEST_F(sys_call_test, close_badfd)
{
	int callnum = 0;
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return 0 == strcmp(evt->get_name(), "close") && m_tid_filter(evt);
	};
	run_callback_t test = [](sinsp* inspector)
	{
		close(-1);
		close(INT_MAX);
	};
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		callnum++;
	};
	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	EXPECT_EQ(4, callnum);
}

TEST_F(sys_call_test, close_badfd_dropping)
{
	int callnum = 0;
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return 0 == strcmp(evt->get_name(), "close") && m_tid_filter(evt);
	};
	run_callback_t test = [](sinsp* inspector)
	{
		inspector->start_dropping_mode(1);
		close(-1);
		close(INT_MAX);
		inspector->stop_dropping_mode();
	};
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		callnum++;
	};
	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	EXPECT_EQ(0, callnum);
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
			EXPECT_TRUE(
			            fds == "0:f1 1:f4" ||
				    fds == "0:p1 1:f4" ||
			            fds == "0:f1 1:p4" ||
				    fds == "0:p1 1:p4"
				    ) << "Value of fds is not one of expected values: " << fds;
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
				// It looks that starting from kernel 4.9, fd is -1 also on 64bit
				EXPECT_TRUE(e->get_param_value_str("fd", false) == "4294967295" ||
							e->get_param_value_str("fd", false) == "-1");
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
				EXPECT_TRUE(e->get_param_value_str("fd", false) == "4294967295" ||
							e->get_param_value_str("fd", false) == "-1");
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
		return evt->get_type() == PPME_SYSCALL_QUOTACTL_X ||
			evt->get_type() == PPME_SYSCALL_QUOTACTL_E;
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		quotactl(QCMD(Q_QUOTAON, USRQUOTA), "/dev/xxx", 2, (caddr_t)"/quota.user"); // 2 => QFMT_VFS_V0
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

				printf("quotactl: on str: %s\n", e->get_param_value_str("cmd").c_str());
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
	auto ret = system("umount /tmp/testquotamnt");
	ret = system("rm -rf /tmp/testquotactl /tmp/testquotamnt");
	// Setup a tmpdisk to test quotas
	char command[] = "dd if=/dev/zero of=/tmp/testquotactl bs=1M count=200 &&\n"
						"echo y | mkfs.ext4 -q /tmp/testquotactl &&\n"
						"mkdir -p /tmp/testquotamnt &&\n"
						"mount -o usrquota,grpquota,loop=/dev/loop0 /tmp/testquotactl /tmp/testquotamnt &&\n"
						"quotacheck -cug /tmp/testquotamnt";
	ret = system(command);
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
		return evt->get_type() == PPME_SYSCALL_QUOTACTL_X ||
			evt->get_type() == PPME_SYSCALL_QUOTACTL_E;
	};

	//
	// TEST CODE
	//
	struct dqblk mydqblk;
	struct dqinfo mydqinfo;
	run_callback_t test = [&](sinsp* inspector)
	{
		quotactl(QCMD(Q_QUOTAON, USRQUOTA), "/dev/loop0", 2, (caddr_t)"/tmp/testquotamnt/aquota.user"); // 2 => QFMT_VFS_V0
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

TEST_F(sys_call_test, getsetresuid_and_gid)
{
	static const uint32_t test_uid = 5454;
	static const uint32_t test_gid = 6565;
	int callnum = 0;
	uint32_t uids[3];
	uint32_t gids[3];
	// Clean environment
	//system("userdel testsetresuid");
	//system("groupdel testsetresgid");
	//usleep(200);
	// Setup a tmpdisk to test quotas
	//char command[] = "useradd -u 5454 testsetresuid &&\n"
	//					"groupadd -g 6565 testsetresgid";
	//int ret = system(command);
	//ASSERT_EQ(0, ret);
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
		auto res = setresuid(test_uid, -1, -1);
		EXPECT_EQ(0, res);
		res = setresgid(test_gid, -1, -1);
		EXPECT_EQ(0, res);
		getresuid(uids,uids+1,uids+2);
		getresgid(gids,gids+1,gids+2);
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
			EXPECT_EQ("<NA>", e->get_param_value_str("ruid"));
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
			EXPECT_EQ("<NA>", e->get_param_value_str("rgid"));
			EXPECT_EQ("-1", e->get_param_value_str("egid", false));
			EXPECT_EQ("<NONE>", e->get_param_value_str("egid"));
			EXPECT_EQ("-1", e->get_param_value_str("sgid", false));
			EXPECT_EQ("<NONE>", e->get_param_value_str("sgid"));
		} else if ( type == PPME_SYSCALL_SETRESGID_X)
		{
			++callnum;
			EXPECT_EQ("0", e->get_param_value_str("res", false));
		} else if ( type == PPME_SYSCALL_GETRESUID_E || type == PPME_SYSCALL_GETRESGID_E )
		{
			++callnum;
		} else if (type == PPME_SYSCALL_GETRESUID_X )
		{
			++callnum;
			EXPECT_EQ("0", e->get_param_value_str("res", false));
			EXPECT_EQ("5454", e->get_param_value_str("ruid", false));
			EXPECT_EQ("<NA>", e->get_param_value_str("ruid"));
			EXPECT_EQ("0", e->get_param_value_str("euid", false));
			EXPECT_EQ("root", e->get_param_value_str("euid"));
			EXPECT_EQ("0", e->get_param_value_str("suid", false));
			EXPECT_EQ("root", e->get_param_value_str("suid"));
		} else if ( type == PPME_SYSCALL_GETRESGID_X )
		{
			++callnum;
			EXPECT_EQ("0", e->get_param_value_str("res", false));
			EXPECT_EQ("6565", e->get_param_value_str("rgid", false));
			EXPECT_EQ("<NA>", e->get_param_value_str("rgid"));
			EXPECT_EQ("0", e->get_param_value_str("egid", false));
			EXPECT_EQ("root", e->get_param_value_str("egid"));
			EXPECT_EQ("0", e->get_param_value_str("sgid", false));
			EXPECT_EQ("root", e->get_param_value_str("sgid"));
		}
	};
	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	EXPECT_EQ(8, callnum);
}

TEST_F(sys_call_test, getsetuid_and_gid)
{
	static const uint32_t test_gid = 6566;
	int callnum = 0;
	// Clean environment
	//system("groupdel getsetuid_and_gid");
	//usleep(200);
	// Setup a tmpdisk to test quotas
	//char command[] = "groupadd -g 6566 getsetuid_and_gid";
	//int ret = system(command);
	//ASSERT_EQ(0, ret);
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
		auto res = setuid(0);
		EXPECT_EQ(0, res);
		res = setgid(test_gid);
		EXPECT_EQ(0, res);
		getuid();
		geteuid();
		getgid();
		getegid();
	};

	//
	// OUTPUT VALIDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();
		switch(type)
		{
		case PPME_SYSCALL_SETUID_E:
			++callnum;
			EXPECT_EQ("0", e->get_param_value_str("uid", false));
			EXPECT_EQ("root", e->get_param_value_str("uid"));
			break;
		case PPME_SYSCALL_SETUID_X:
			++callnum;
			EXPECT_EQ("0", e->get_param_value_str("res", false));
			break;
		case PPME_SYSCALL_SETGID_E:
			++callnum;
			EXPECT_EQ("6566", e->get_param_value_str("gid", false));
			EXPECT_EQ("<NA>", e->get_param_value_str("gid"));
			break;
		case PPME_SYSCALL_SETGID_X:
			++callnum;
			EXPECT_EQ("0", e->get_param_value_str("res", false));
			break;
		case PPME_SYSCALL_GETUID_X:
			++callnum;
			EXPECT_EQ("0", e->get_param_value_str("uid", false));
			EXPECT_EQ("root", e->get_param_value_str("uid"));
			break;
		case PPME_SYSCALL_GETEUID_X:
			++callnum;
			EXPECT_EQ("0", e->get_param_value_str("euid", false));
			EXPECT_EQ("root", e->get_param_value_str("euid"));
			break;
		case PPME_SYSCALL_GETGID_X:
			++callnum;
			EXPECT_EQ("6566", e->get_param_value_str("gid", false));
			EXPECT_EQ("<NA>", e->get_param_value_str("gid"));
			break;
		case PPME_SYSCALL_GETEGID_X:
			++callnum;
			EXPECT_EQ("6566", e->get_param_value_str("egid", false));
			EXPECT_EQ("<NA>", e->get_param_value_str("egid"));
			break;
		case PPME_SYSCALL_GETUID_E:
		case PPME_SYSCALL_GETEUID_E:
		case PPME_SYSCALL_GETGID_E:
		case PPME_SYSCALL_GETEGID_E:
			++callnum;
			break;
		}
	};
	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	EXPECT_EQ(12, callnum);
}

TEST_F(sys_call_test, ppoll_timeout)
{
	int callnum = 0;
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return evt->get_type() == PPME_SYSCALL_PPOLL_E ||
				evt->get_type() == PPME_SYSCALL_PPOLL_X;
	};

	run_callback_t test = [](sinsp* inspector)
	{
		proc helper_proc { "./test_helper", { "ppoll_timeout", }};
		auto handle = start_process(&helper_proc);
		get<0>(handle).wait();
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_PPOLL_E)
		{
			//
			// stdin and stdout can be a file or a fifo depending
			// on how the tests are invoked
			//
			string fds = e->get_param_value_str("fds");
			EXPECT_EQ("3:p1 4:p4", fds);
			EXPECT_EQ("1000000", e->get_param_value_str("timeout", false));
			EXPECT_EQ("SIGHUP SIGCHLD", e->get_param_value_str("sigmask", false));
			callnum++;
		}
		else if(type == PPME_SYSCALL_PPOLL_X)
		{
			int64_t res = NumberParser::parse(e->get_param_value_str("res"));

			EXPECT_GT(res, 0);
			EXPECT_LE(res, 2);

			string fds = e->get_param_value_str("fds");

			switch(res)
			{
				case 1:
					EXPECT_EQ("4:p4", fds);
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

#ifdef __x86_64__

TEST_F(sys_call_test32, execve_ia32_emulation)
{
	int callnum = 0;

	//
	// FILTER
	//
	sinsp_filter_compiler compiler(NULL, "evt.type=execve and proc.apid=" + to_string(getpid()));
	unique_ptr<sinsp_filter> is_subprocess_execve(compiler.compile());
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return is_subprocess_execve->run(evt);
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		auto ret = system("./resources/execve32 ./resources/execve ./resources/execve32");
		EXPECT_EQ(0, ret);
	};

	//
	// OUTPUT VALIDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();
		auto tinfo = e->get_thread_info(true);
		//printf("%s Type is %u\n", e->get_thread_info(true)->m_exe.c_str(), type);
		if (type == PPME_SYSCALL_EXECVE_19_E || type == PPME_SYSCALL_EXECVE_18_E || type == PPME_SYSCALL_EXECVE_17_E)
		{
			++callnum;
			switch(callnum)
			{
			case 1:
				EXPECT_EQ(tinfo->m_comm, "tests");
				break;
			case 3:
				EXPECT_EQ(tinfo->m_comm, "sh");
				break;
			case 5:
				EXPECT_EQ(tinfo->m_comm, "execve32");
				break;
			case 7:
				EXPECT_EQ(tinfo->m_comm, "execve");
				break;
			}
		}
		else if ( type == PPME_SYSCALL_EXECVE_19_X || type == PPME_SYSCALL_EXECVE_18_X || type == PPME_SYSCALL_EXECVE_17_X)
		{
			++callnum;
			EXPECT_EQ("0", e->get_param_value_str("res", false));
			auto comm = e->get_param_value_str("comm", false);
			switch(callnum)
			{
			case 2:
				EXPECT_EQ(comm, "sh");
				break;
			case 4:
				EXPECT_EQ(comm, "execve32");
				break;
			case 6:
				EXPECT_EQ(comm, "execve");
				break;
			case 8:
				EXPECT_EQ(comm, "execve32");
				break;
			}
		}
	};
	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	EXPECT_EQ(8, callnum);
}

TEST_F(sys_call_test, failing_execve)
{
	int callnum = 0;

	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return m_tid_filter(evt);
	};

	const char *eargv[] = { "/non/existent",
				"arg0",
				"arg1",
				"",
				"arg3",
				NULL
	};

	const char *eenvp[] = { "env0",
				"env1",
				"",
				"env3",
				NULL
	};

	//
	// Touch the memory so it won't generate a PF in the driver
	//
	printf("%s %s %s %s %s\n", eargv[0], eargv[1], eargv[2], eargv[3], eargv[4]);
	printf("%s %s %s %s\n", eenvp[0], eenvp[1], eenvp[2], eenvp[3]);

	run_callback_t test = [&](sinsp* inspector)
	{

		int ret = execve(eargv[0],
				 (char * const *) eargv,
				 (char * const *) eenvp);
		ASSERT_TRUE(ret < 0);
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt *e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_EXECVE_19_E ||
		   type == PPME_SYSCALL_EXECVE_18_E)
		{
			++callnum;

			string filename = e->get_param_value_str("filename");
			EXPECT_EQ(filename, eargv[0]);
		}
		else if (type == PPME_SYSCALL_EXECVE_19_X ||
			 type == PPME_SYSCALL_EXECVE_18_X)
		{
			++callnum;

			string res = e->get_param_value_str("res");
			EXPECT_EQ(res, "ENOENT");

			string exe = e->get_param_value_str("exe");
			EXPECT_EQ(exe, eargv[0]);

			string args = e->get_param_value_str("args");
			EXPECT_EQ(args, "arg0.arg1..arg3.");

			string env = e->get_param_value_str("env");
			EXPECT_EQ(env, "env0.env1..env3.");
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	EXPECT_EQ(2, callnum);
}

TEST_F(sys_call_test32, failing_execve)
{
	int callnum = 0;

	//
	// FILTER
	//
	sinsp_filter_compiler compiler(NULL, "evt.type=execve and proc.apid=" + to_string(getpid()));
	unique_ptr<sinsp_filter> is_subprocess_execve(compiler.compile());
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return is_subprocess_execve->run(evt);
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		auto ret = system("./resources/execve32_fail");
		ASSERT_TRUE(ret > 0);
		ret = system("./resources/execve32 ./fail");
		ASSERT_TRUE(ret > 0);
	};

	//
	// OUTPUT VALIDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();
		auto tinfo = e->get_thread_info(true);
		if (type == PPME_SYSCALL_EXECVE_19_E || type == PPME_SYSCALL_EXECVE_18_E || type == PPME_SYSCALL_EXECVE_17_E)
		{
			++callnum;
			switch(callnum)
			{
			case 1:
				EXPECT_EQ(tinfo->m_comm, "tests");
				break;
			case 3:
				EXPECT_EQ(tinfo->m_comm, "sh");
				break;
			case 5:
				EXPECT_EQ(tinfo->m_comm, "tests");
				break;
			case 7:
				EXPECT_EQ(tinfo->m_comm, "sh");
				break;
			case 9:
				EXPECT_EQ(tinfo->m_comm, "execve32");
				break;
			default:
				FAIL() << "Wrong execve entry callnum (" << callnum << ")";
			}
		}
		else if ( type == PPME_SYSCALL_EXECVE_19_X || type == PPME_SYSCALL_EXECVE_18_X || type == PPME_SYSCALL_EXECVE_17_X)
		{
			++callnum;

			auto res = e->get_param_value_str("res", false);
			auto comm = e->get_param_value_str("comm", false);
			auto exe = e->get_param_value_str("exe", false);
			switch(callnum)
			{
			case 2:
				EXPECT_EQ("0", res);
				EXPECT_EQ(comm, "sh");
				break;
			case 4:
				EXPECT_EQ("-2", res);
				EXPECT_EQ(comm, "sh");
				EXPECT_EQ(exe, "./resources/execve32_fail");
				break;
			case 6:
				EXPECT_EQ("0", res);
				EXPECT_EQ(comm, "sh");
				break;
			case 8:
				EXPECT_EQ("0", res);
				EXPECT_EQ(comm, "execve32");
				EXPECT_EQ(exe, "./resources/execve32");
				break;
			case 10:
				EXPECT_EQ("-2", res);
				EXPECT_EQ(comm, "execve32");
				EXPECT_EQ(exe, "./fail");
				break;
			default:
				FAIL() << "Wrong execve exit callnum (" << callnum << ")";
			}
		}
	};
	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	EXPECT_EQ(10, callnum);
}

TEST_F(sys_call_test, large_execve)
{
	const int buf_size = 100 * 1024;
	const int driver_truncation_size = getpagesize();
	const string non_existing_binary = "/non/existent";
	const string existing_binary = "/bin/true";

	int ctid;
	int callnum = 0;

	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return evt->get_tid() == ctid;
	};

	srandom(42);

	string buf;
	while(buf.length() < buf_size)
	{
		buf.append(Poco::NumberFormatter::format(random()));
	}

	run_callback_t test = [&](sinsp* inspector)
	{
		ctid = fork();

		if(ctid < 0)
		{
			FAIL();
		}

		if(ctid == 0)
		{
			{
				const char *eargv[] = { non_existing_binary.c_str(),
							buf.c_str(),
							NULL };

				const char *eenvp[] = { buf.c_str(),
							NULL };

				int ret = execve(eargv[0],
						 (char * const *) eargv,
						 (char * const *) eenvp);
				ASSERT_TRUE(ret < 0);
			}

			{
				const char *eargv[] = { existing_binary.c_str(),
							buf.c_str(),
							NULL };

				const char *eenvp[] = { buf.c_str(),
							NULL };

				int ret = execve(eargv[0],
						 (char * const *) eargv,
						 (char * const *) eenvp);
				ASSERT_TRUE(ret == 0);
			}
		}
		else
		{
			wait(NULL);
			sleep(1);
		}
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt *e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_EXECVE_19_E ||
		   type == PPME_SYSCALL_EXECVE_18_E)
		{
			++callnum;

			string filename = e->get_param_value_str("filename");

			if(callnum == 1)
			{
				EXPECT_EQ(filename, non_existing_binary);
			}
			else if(callnum == 3)
			{
				EXPECT_EQ(filename, existing_binary);
			}
			else
			{
				FAIL();
			}
		}
		else if (type == PPME_SYSCALL_EXECVE_19_X ||
			 type == PPME_SYSCALL_EXECVE_18_X)
		{
			++callnum;

			string exe = e->get_param_value_str("exe");
			string args = e->get_param_value_str("args");
			string env = e->get_param_value_str("env");

			if(callnum == 2)
			{
				if(scap_get_bpf_probe_from_env() == NULL)
				{
					//
					// The driver doesn't have the correct behavior
					// for failed execves, it discards arguments
					// instead of truncating them if they're too big
					//
					EXPECT_EQ(exe, "");
					EXPECT_EQ(args, "");
					EXPECT_EQ(env, "");
				}
				else
				{
					EXPECT_EQ(exe, non_existing_binary.c_str());
					EXPECT_EQ(args, buf.substr(0, driver_truncation_size - non_existing_binary.length() - 2) + ".");
					EXPECT_EQ(env, buf.substr(0, driver_truncation_size - 1) + ".");
				}
			}
			else if(callnum == 4)
			{
				EXPECT_EQ(exe, existing_binary);
				EXPECT_EQ(args, buf.substr(0, driver_truncation_size - existing_binary.length() - 2) + ".");
				EXPECT_EQ(env, buf.substr(0, driver_truncation_size - 1) + ".");
			}
			else
			{
				FAIL();
			}
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	EXPECT_EQ(4, callnum);
}

TEST_F(sys_call_test32, mmap)
{
	int callnum = 0;
	int errno2;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		auto tinfo = evt->get_thread_info(false);
		return tinfo && tinfo->m_comm == "test_helper_32" && m_proc_started_filter(evt);
	};

	void* p;

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		proc test_proc("./test_helper_32", {"mmap_test", });
		auto handle = start_process(&test_proc);
		Poco::PipeInputStream istr(*get<1>(handle));
		istr >> errno2;
		istr >> p;
		get<0>(handle).wait();
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

TEST_F(sys_call_test32, quotactl_ko)
{
	int callnum = 0;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return evt->get_type() == PPME_SYSCALL_QUOTACTL_X ||
			evt->get_type() == PPME_SYSCALL_QUOTACTL_E;
	};

	//
	// TEST CODE
	//
	proc helper { "./test_helper_32", { "quotactl_ko", }};
	run_callback_t test = [&](sinsp* inspector)
	{
		auto handle = start_process(&helper);
		get<0>(handle).wait();
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

TEST_F(sys_call_test32, quotactl_ok)
{
	int callnum = 0;

	// Clean environment
	auto ret = system("umount /tmp/testquotamnt");
	ret = system("rm -rf /tmp/testquotactl /tmp/testquotamnt");
	// Setup a tmpdisk to test quotas
	char command[] = "dd if=/dev/zero of=/tmp/testquotactl bs=1M count=200 &&\n"
						"echo y | mkfs.ext4 -q /tmp/testquotactl &&\n"
						"mkdir -p /tmp/testquotamnt &&\n"
						"mount -o usrquota,grpquota,loop=/dev/loop0 /tmp/testquotactl /tmp/testquotamnt &&\n"
						"quotacheck -cug /tmp/testquotamnt";
	ret = system(command);
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
		return evt->get_type() == PPME_SYSCALL_QUOTACTL_X ||
			evt->get_type() == PPME_SYSCALL_QUOTACTL_E;
	};

	//
	// TEST CODE
	//
	proc helper_proc { "./test_helper_32", { "quotactl_ok", }};
	struct dqblk mydqblk, otherdqblk;
	struct dqinfo mydqinfo, otherdqinfo;
	run_callback_t test = [&](sinsp* inspector)
	{
		auto handle = start_process(&helper_proc);
		auto pipe = get<1>(handle);

		EXPECT_EQ(pipe->readBytes(&mydqblk.dqb_bhardlimit, sizeof(uint64_t)), (int)sizeof(uint64_t));
		EXPECT_EQ(pipe->readBytes(&mydqblk.dqb_bsoftlimit, sizeof(uint64_t)), (int)sizeof(uint64_t));
		EXPECT_EQ(pipe->readBytes(&mydqblk.dqb_curspace, sizeof(uint64_t)), (int)sizeof(uint64_t));
		EXPECT_EQ(pipe->readBytes(&mydqblk.dqb_ihardlimit, sizeof(uint64_t)), (int)sizeof(uint64_t));
		EXPECT_EQ(pipe->readBytes(&mydqblk.dqb_isoftlimit, sizeof(uint64_t)), (int)sizeof(uint64_t));
		EXPECT_EQ(pipe->readBytes(&mydqblk.dqb_btime, sizeof(uint64_t)), (int)sizeof(uint64_t));
		EXPECT_EQ(pipe->readBytes(&mydqblk.dqb_itime, sizeof(uint64_t)), (int)sizeof(uint64_t));
		EXPECT_EQ(pipe->readBytes(&mydqinfo.dqi_bgrace, sizeof(uint64_t)), (int)sizeof(uint64_t));
		EXPECT_EQ(pipe->readBytes(&mydqinfo.dqi_igrace, sizeof(uint64_t)), (int)sizeof(uint64_t));
		get<0>(handle).wait();
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
				otherdqblk.dqb_bhardlimit = *reinterpret_cast<uint64_t*>(e->get_param_value_raw("dqb_bhardlimit")->m_val);
				otherdqblk.dqb_bsoftlimit = *reinterpret_cast<uint64_t*>(e->get_param_value_raw("dqb_bsoftlimit")->m_val);
				otherdqblk.dqb_curspace = *reinterpret_cast<uint64_t*>(e->get_param_value_raw("dqb_curspace")->m_val);
				otherdqblk.dqb_ihardlimit = *reinterpret_cast<uint64_t*>(e->get_param_value_raw("dqb_ihardlimit")->m_val);
				otherdqblk.dqb_isoftlimit = *reinterpret_cast<uint64_t*>(e->get_param_value_raw("dqb_isoftlimit")->m_val);
				otherdqblk.dqb_btime = *reinterpret_cast<uint64_t*>(e->get_param_value_raw("dqb_btime")->m_val);
				otherdqblk.dqb_itime = *reinterpret_cast<uint64_t*>(e->get_param_value_raw("dqb_itime")->m_val);
				break;
			case 6:
				EXPECT_EQ("0", e->get_param_value_str("res", false));
				EXPECT_EQ("/dev/loop0", e->get_param_value_str("special"));
				otherdqinfo.dqi_bgrace = *reinterpret_cast<uint64_t*>(e->get_param_value_raw("dqi_bgrace")->m_val);
				otherdqinfo.dqi_igrace = *reinterpret_cast<uint64_t*>(e->get_param_value_raw("dqi_igrace")->m_val);
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
	EXPECT_EQ(otherdqblk.dqb_bhardlimit, mydqblk.dqb_bhardlimit);
	EXPECT_EQ(otherdqblk.dqb_bsoftlimit, mydqblk.dqb_bsoftlimit);
	EXPECT_EQ(otherdqblk.dqb_curspace, mydqblk.dqb_curspace);
	EXPECT_EQ(otherdqblk.dqb_ihardlimit, mydqblk.dqb_ihardlimit);
	EXPECT_EQ(otherdqblk.dqb_isoftlimit, mydqblk.dqb_isoftlimit);
	EXPECT_EQ(otherdqblk.dqb_btime, mydqblk.dqb_btime);
	EXPECT_EQ(otherdqblk.dqb_itime, mydqblk.dqb_itime);
	EXPECT_EQ(otherdqinfo.dqi_bgrace, mydqinfo.dqi_bgrace);
	EXPECT_EQ(otherdqinfo.dqi_igrace, mydqinfo.dqi_igrace);
}

TEST_F(sys_call_test32, ppoll_timeout)
{
	int callnum = 0;
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		auto tinfo = evt->get_thread_info(false);
		return (evt->get_type() == PPME_SYSCALL_PPOLL_E ||
				evt->get_type() == PPME_SYSCALL_PPOLL_X) &&
			tinfo != nullptr && tinfo->m_comm == "test_helper_32";
	};

	run_callback_t test = [](sinsp* inspector)
	{
		proc helper_proc { "./test_helper_32", { "ppoll_timeout", }};
		auto handle = start_process(&helper_proc);
		get<0>(handle).wait();
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_PPOLL_E)
		{
			//
			// stdin and stdout can be a file or a fifo depending
			// on how the tests are invoked
			//
			string fds = e->get_param_value_str("fds");
			EXPECT_EQ("3:p1 4:p4", fds);
			EXPECT_EQ("1000000", e->get_param_value_str("timeout", false));
			EXPECT_EQ("SIGHUP SIGCHLD", e->get_param_value_str("sigmask", false));
			callnum++;
		}
		else if(type == PPME_SYSCALL_PPOLL_X)
		{
			int64_t res = NumberParser::parse(e->get_param_value_str("res"));

			EXPECT_GT(res, 0);
			EXPECT_LE(res, 2);

			string fds = e->get_param_value_str("fds");

			switch(res)
			{
				case 1:
					EXPECT_EQ("4:p4", fds);
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
#endif

TEST_F(sys_call_test, get_n_tracepoint_hit_smoke)
{
	int callnum = 0;
	vector<long> old_evts;
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return false;
	};
	run_callback_t test = [&](sinsp* inspector)
	{
		uint64_t t_finish = sinsp_utils::get_current_time_ns() + 500000000;
		auto ncpu = inspector->get_machine_info()->num_cpus;
		// just test the tracepoint hit
		auto evts_vec = inspector->get_n_tracepoint_hit();
		for(unsigned j = 0; j < ncpu; ++j)
		{
			EXPECT_GE(evts_vec[j], 0) << "cpu=" << j;
		}
		while (sinsp_utils::get_current_time_ns() < t_finish)
		{
			tee(-1, -1, 0, 0);
		}
		auto evts_vec2 = inspector->get_n_tracepoint_hit();
		for(unsigned j = 0; j < ncpu; ++j)
		{
			EXPECT_GE(evts_vec2[j], evts_vec[j]) << "cpu=" << j;
		}
		old_evts = evts_vec2;
	};
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		callnum++;
	};
	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

	// rerun again to check that counters are properly reset when userspace shutdowns
	test = [&](sinsp* inspector)
	{
		// we can't compare by cpu because processes may be scheduled on other cpus
		// let's just compare the whole sum for now
		auto evts_vec = inspector->get_n_tracepoint_hit();
		auto new_count = std::accumulate(evts_vec.begin(), evts_vec.end(), 0);
		auto old_count = std::accumulate(old_evts.begin(), old_evts.end(), 0);
		EXPECT_LT(new_count, old_count);
	};
	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	EXPECT_EQ(0, callnum);
}

TEST_F(sys_call_test, DISABLED_get_n_tracepoint_hit_counts)
{
	static const int SYSCALL_COUNT = 1000000;
	int callnum = 0;
	bool started = false;
	vector<long> old_evts;

	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return m_tid_filter(evt) &&
				evt->get_type() == PPME_SYSCALL_CLOSE_X &&
				evt->get_param_value_str("res", false) != "0";
	};
	run_callback_t test = [&](sinsp* inspector)
	{
		// Use close events as sentinels
		close(-34);
		for(int j = 0; j < SYSCALL_COUNT; ++j)
		{
			open("/tmp/ksdlajdklsa", 0);
		}
		close(-34);
	};
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		if(started)
		{
			auto new_evts = param.m_inspector->get_n_tracepoint_hit();
			int sum = 0;
			for(unsigned j = 0; j < old_evts.size(); ++j)
			{
				sum += (new_evts[j] - old_evts[j]);
			}
			// Sum should at least greater than syscall_count*2 since
			// we generated those
			EXPECT_GT(sum, SYSCALL_COUNT*2);
		}
		else
		{
			old_evts = param.m_inspector->get_n_tracepoint_hit();
			started = true;
		}
		++callnum;
	};
	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	EXPECT_EQ(2, callnum);
	EXPECT_TRUE(started);
}

TEST_F(sys_call_test, setns_test)
{
	int callnum = 0;
	int fd;
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return m_tid_filter(evt) &&
				( evt->get_type() == PPME_SYSCALL_SETNS_E ||
					evt->get_type() == PPME_SYSCALL_SETNS_X );
	};
	run_callback_t test = [&](sinsp* inspector)
	{
		fd = open("/proc/self/ns/net", O_RDONLY);
		ASSERT_NE(0, fd);
		ASSERT_EQ(0, setns(fd, CLONE_NEWNET));
		ASSERT_EQ(0, close(fd));
	};
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();
		switch(type)
		{
			case PPME_SYSCALL_SETNS_E:
				EXPECT_EQ("<f>/proc/self/ns/net", e->get_param_value_str("fd"));
				break;
			case PPME_SYSCALL_SETNS_X:
				EXPECT_EQ("0", e->get_param_value_str("res"));
				break;
		}
		++callnum;
	};
	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	EXPECT_EQ(2, callnum);
}

TEST_F(sys_call_test, unshare_)
{
	int callnum = 0;
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		auto tinfo = evt->get_thread_info(true);
		return tinfo->get_comm() == "tests" && ( evt->get_type() == PPME_SYSCALL_UNSHARE_E ||
					evt->get_type() == PPME_SYSCALL_UNSHARE_X );
	};
	run_callback_t test = [&](sinsp* inspector)
	{
		auto child = fork();
		if(child == 0)
		{
			unshare(CLONE_NEWUTS);
			exit(0);
		}
		waitpid(child, NULL, 0);
	};
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();
		switch(type)
		{
			case PPME_SYSCALL_UNSHARE_E:
				EXPECT_EQ("CLONE_NEWUTS", e->get_param_value_str("flags"));
				break;
			case PPME_SYSCALL_UNSHARE_X:
				EXPECT_EQ("0", e->get_param_value_str("res"));
				break;
		}
		++callnum;
	};
	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	EXPECT_EQ(2, callnum);
}

TEST_F(sys_call_test, clone_tid_vtid)
{
	// this is racy :/ run in a loop to give the test a chance to fail
	// see vtidcollision.c for the description of the test scenario

	int loops = 10;
	volatile bool failed = false;

	while(loops --> 0 && !failed)
	{
		int vpid=0, pid=0, ppid=0;
		proc test_proc = proc("./vtidcollision", {});
		volatile bool done = false;

		event_filter_t filter = [&](sinsp_evt * evt)
		{
			return !done && pid != 0 && evt->get_tid() == pid;
		};
		run_callback_t test = [&](sinsp* inspector)
		{
			auto test_start = time(nullptr);
			auto handle = start_process(&test_proc);
			char buf[256];
			get<0>(handle).wait();
			auto nread = get<1>(handle)->readBytes(buf, sizeof(buf));
			EXPECT_GT(nread, 0);
			EXPECT_LE(nread, sizeof(buf));
			sscanf(buf, "vpid %d pid %d ppid %d", &vpid, &pid, &ppid);
			while(!done && time(nullptr) - test_start < 5) {
				usleep(100000);
			}
		};
		captured_event_callback_t callback = [&](const callback_param& param)
		{
			done = true;
			failed = true;

			// look up the thread by vpid instead of pid (SMAGENT-1582)
			auto tinfo = param.m_inspector->get_thread_ref(vpid, false, true);
			if (tinfo != nullptr)
			{
				// if uid == ppid (and it's legit), we're incredibly unlucky
				ASSERT_NE(ppid, tinfo->m_uid);
			}

			// need ASSERT_XXX above to skip this line in case of failure:
			failed = false;
		};
		ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
		if(failed)
		{
			break;
		}
		fprintf(stderr, "%d runs remaining\n", loops);
	}
}

TEST_F(sys_call_test, thread_lookup_static)
{
	struct stat s = {};
	char proc[] = "resources/_proc";
	if (stat(proc, &s) != 0)
	{
		fprintf(stderr, "%s not found, skipping test\n", proc);
		FAIL();
	}

	char err_buf[SCAP_LASTERR_SIZE];
	int rc = 0;
	scap_open_args oargs;
	oargs.mode = SCAP_MODE_LIVE;
	oargs.fname = nullptr;
	oargs.proc_callback = nullptr;
	oargs.proc_callback_context = nullptr;
	oargs.bpf_probe = nullptr;
	oargs.import_users = false;
	oargs.suppressed_comms[0] = nullptr;

	scap_t* scap = scap_open(oargs, err_buf, &rc);
	ASSERT_NE(nullptr, scap);

	scap_threadinfo* scap_tinfo = nullptr;
	ASSERT_EQ(SCAP_SUCCESS, scap_proc_read_thread(scap, proc, 1, &scap_tinfo, err_buf, false));
	EXPECT_EQ(1, scap_tinfo->tid);
	EXPECT_EQ(1, scap_tinfo->pid);
	EXPECT_EQ(1, scap_tinfo->vtid);
	EXPECT_EQ(0, scap_tinfo->ptid);

	ASSERT_EQ(SCAP_SUCCESS, scap_proc_read_thread(scap, proc, 62725, &scap_tinfo, err_buf, false));
	EXPECT_EQ(62725, scap_tinfo->tid);
	EXPECT_EQ(62725, scap_tinfo->pid);
	EXPECT_EQ(62725, scap_tinfo->vtid);
	EXPECT_EQ(1, scap_tinfo->ptid);

	ASSERT_EQ(SCAP_SUCCESS, scap_proc_read_thread(scap, proc, 62727, &scap_tinfo, err_buf, false));
	EXPECT_EQ(62727, scap_tinfo->tid);
	EXPECT_EQ(62725, scap_tinfo->pid);
	EXPECT_EQ(62727, scap_tinfo->vtid);
	EXPECT_EQ(1, scap_tinfo->ptid);

	scap_close(scap);
}

TEST_F(sys_call_test, thread_lookup_live)
{
	char err_buf[SCAP_LASTERR_SIZE];
	int rc = 0;
	scap_open_args oargs;
	oargs.mode = SCAP_MODE_LIVE;
	oargs.fname = nullptr;
	oargs.proc_callback = nullptr;
	oargs.proc_callback_context = nullptr;
	oargs.bpf_probe = nullptr;
	oargs.import_users = false;
	oargs.suppressed_comms[0] = nullptr;

	scap_t* scap = scap_open(oargs, err_buf, &rc);
	ASSERT_NE(nullptr, scap);

	scap_threadinfo* scap_tinfo = nullptr;
	char proc[] = "/proc";

	std::unordered_set<int64_t> seen_tids;

	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return evt->get_type() != PPME_PROCEXIT_1_E && evt->get_tid() > 0;
	};
	run_callback_t test = [&](sinsp* inspector)
	{
		// a very short sleep to gather some events,
		// we'll take much longer than this to process them all
		usleep(1000);
	};
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		auto tid = e->get_tid();
		if (!seen_tids.insert(tid).second)
		{
			return;
		}
		fprintf(stderr, "looking up tid %ld in /proc\n", tid);
		if (scap_proc_read_thread(scap, proc, tid, &scap_tinfo, err_buf, false) == SCAP_SUCCESS)
		{
			auto tinfo = e->get_thread_info(false);
			if(!tinfo)
			{
				return;
			}
			EXPECT_NE(0, scap_tinfo->tid);
			EXPECT_NE(0, scap_tinfo->pid);
			EXPECT_NE(0, scap_tinfo->vtid);
			EXPECT_NE(0, scap_tinfo->ptid);
			EXPECT_EQ(tinfo->m_tid, scap_tinfo->tid);
			EXPECT_EQ(tinfo->m_pid, scap_tinfo->pid);
			EXPECT_EQ(tinfo->m_vtid, scap_tinfo->vtid);
			EXPECT_EQ(tinfo->m_ptid, scap_tinfo->ptid);
		}
	};
	before_close_t before_close = [&](sinsp* inspector) {
		// close scap to maintain the num_consumers at exit == 0 assertion
		scap_close(scap);
	};

	ASSERT_EQ(SCAP_SUCCESS, scap_proc_read_thread(scap, proc, getpid(), &scap_tinfo, err_buf, false));
	EXPECT_EQ(getpid(), scap_tinfo->tid);
	EXPECT_EQ(getpid(), scap_tinfo->pid);
	EXPECT_EQ(getpid(), scap_tinfo->vtid);
	EXPECT_EQ(getppid(), scap_tinfo->ptid);

	ASSERT_EQ(SCAP_SUCCESS, scap_proc_read_thread(scap, proc, 1, &scap_tinfo, err_buf, false));
	EXPECT_EQ(1, scap_tinfo->tid);
	EXPECT_EQ(1, scap_tinfo->pid);
	EXPECT_EQ(1, scap_tinfo->vtid);
	EXPECT_EQ(0, scap_tinfo->ptid);

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter, event_capture::do_nothing, before_close);});
}