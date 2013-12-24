#include "sys_call_test.h"
#include <gtest.h>
#include <algorithm>
#include "event_capture.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <event.h>
#include <Poco/Process.h>
#include <Poco/PipeStream.h>
#include <Poco/StringTokenizer.h>
#include <Poco/NumberFormatter.h>
#include <list>
#include <cassert>
#include <sinsp.h>
#include <sinsp_int.h>
#include <connectinfo.h>
#include <tuple>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/syscall.h>

using namespace std;
using Poco::StringTokenizer;
using Poco::NumberFormatter;

#include "sinsp_int.h"
#include "analyzer_thread.h"

#define NAME "/tmp/python_unix_sockets_example"
#define PAYLOAD "0123456789QWERTYUIOPASDFGHJKLZXCVBNM"

#define SERVER_PORT     3555
#define SERVER_PORT_STR "3555"
#define PAYLOAD         "0123456789QWERTYUIOPASDFGHJKLZXCVBNM"
#define BUFFER_LENGTH    (sizeof(PAYLOAD) - 1)
#define FALSE           0
#define SERVER_NAME     "192.168.22.167"
#define NTRANSACTIONS   2

class unix_server
{
public:
	void run()
	{
		int sockfd;
		int newsockfd;
		int servlen;
		int n;
		socklen_t clilen;
		struct sockaddr_un cli_addr;
		struct sockaddr_un serv_addr;
		char buf[80];
		unlink(NAME);

		m_tid = syscall(SYS_gettid);


		if((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		{
			FAIL() << "couldn't create socket";
		}
		int yes = 1;
		if(setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(int)) == -1)
		{
			FAIL() << "sockopt";
		}
		bzero((char *) &serv_addr, sizeof(serv_addr));
		serv_addr.sun_family = AF_UNIX;
		strcpy(serv_addr.sun_path, NAME);
		servlen = strlen(serv_addr.sun_path) + sizeof(serv_addr.sun_family);
		if(::bind(sockfd, (struct sockaddr *)&serv_addr, servlen) < 0)
		{
			FAIL() << "couldn't bind socket";
		}
		listen(sockfd, 5);
		clilen = sizeof(cli_addr);
		m_server_ready.set();
		newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
		if(newsockfd < 0)
		{
			FAIL() << "error while accepting";
		}
		m_server_continue.wait();
		n = read(newsockfd, buf, 80);
		write(newsockfd, buf, n);
		close(newsockfd);
		close(sockfd);
		unlink(NAME);
	}

	void wait_for_server_ready()
	{
		m_server_ready.wait();
	}

	void signal_continue()
	{
		m_server_continue.set();
	}

	int64_t get_tid()
	{
		return m_tid;
	}

private:
	Poco::Event m_server_ready;
	Poco::Event m_server_continue;
	int64_t m_tid;
};

class unix_client
{
public:
	void run()
	{
		int sockfd, servlen;
		size_t n;
		struct sockaddr_un  serv_addr;
		char buffer[82];
		int res;

		m_tid = syscall(SYS_gettid);

		bzero((char *)&serv_addr, sizeof(serv_addr));
		serv_addr.sun_family = AF_UNIX;
		strcpy(serv_addr.sun_path, NAME);
		servlen = strlen(serv_addr.sun_path) + sizeof(serv_addr.sun_family);
		if((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		{
			FAIL() << "Creating socket";
		}
		if((res = connect(sockfd, (struct sockaddr *)&serv_addr, servlen)) < 0)
		{
			FAIL() << "Couldn't connect " << res;
		}
		m_client_ready.set();
		m_client_continue.wait();
		write(sockfd, PAYLOAD, sizeof(PAYLOAD) - 1);
		n = read(sockfd, buffer, 80);
		ASSERT_EQ(sizeof(PAYLOAD)-1,n);
		close(sockfd);
	}

	void signal_continue()
	{
		m_client_continue.set();
	}

	void wait_for_client_ready()
	{
		m_client_ready.wait();
	}

	int64_t get_tid()
	{
		return m_tid;
	}
private:
	Poco::Event m_client_ready;
	Poco::Event m_client_continue;
	int64_t m_tid;
};


TEST_F(sys_call_test, unix_client_server)
{
	int32_t callnum = 0;
	int state = 0;
	bool first_connect_or_accept_seen = true;
	string sport;

	string src_addr;
	string dest_addr;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		sinsp_threadinfo *info = evt->get_thread_info(false);
		if(info)
		{
			if(info->get_comm() == "python" && info->m_args.size() == 1)
			{
				return ends_with(info->m_args[0], "unix_server.py") || ends_with(info->m_args[0], "unix_client.py");				
			}
		}

		return false;
	};

	//
	// INITIALIZATION
	//
	run_callback_t test = [](sinsp* inspector)
	{
		process_list_t procs;
		procs.push_back(proc("python", args() << "resources/unix_server.py"));
		procs.push_back(proc("python", args() << "resources/unix_client.py"));
		run_processes(procs);
	};

	//
	// OUTPUT VALIDATION
	//
	captured_event_callback_t callback = [&](const callback_param & param)
	{
		sinsp_evt *evt = param.m_evt;

		if(evt->get_type() == PPME_SOCKET_CONNECT_X)
		{
			string tuple = evt->get_param_value_str("tuple");
			string addrs = tuple.substr(0, tuple.find(" "));
			string file = tuple.substr(tuple.find(" ") + 1);

			EXPECT_EQ(NAME, file);

			StringTokenizer tst(addrs, ">");
			EXPECT_EQ(2, (int)tst.count());
			string srcstr = tst[0].substr(0, tst[0].size() - 1);
			string dststr = tst[1];

			EXPECT_EQ('u', srcstr[0]);
			EXPECT_NE("u0000000000000000", srcstr);
			EXPECT_NE("u0000000000000000", dststr);

			//
			// connect() and accept() can return
			// in a different order
			//
			if(first_connect_or_accept_seen)
			{
				first_connect_or_accept_seen = false;
				src_addr = srcstr.substr(1);
				dest_addr = dststr;
			}
			else
			{
				EXPECT_EQ(src_addr, srcstr.substr(1));
				EXPECT_EQ(dest_addr, dststr);				
			}

			callnum++;
		}
		else if(evt->get_type() == PPME_SOCKET_ACCEPT_X)
		{
			string tuple = evt->get_param_value_str("tuple");
			string addrs = tuple.substr(0, tuple.find(" "));
			string file = tuple.substr(tuple.find(" ") + 1);

			EXPECT_EQ(NAME, file);

			StringTokenizer tst(addrs, ">");
			EXPECT_EQ(2, (int)tst.count());
			string srcstr = tst[0].substr(0, tst[0].size() - 1);
			string dststr = tst[1];

			EXPECT_EQ('u', srcstr[0]);

			EXPECT_NE("u0000000000000000", srcstr);
			EXPECT_NE("u0000000000000000", dststr);

			//
			// connect() and accept() can return
			// in a different order
			//
			if(first_connect_or_accept_seen)
			{
				first_connect_or_accept_seen = false;
				src_addr = srcstr.substr(1);
				dest_addr = dststr;
			}
			else
			{
				EXPECT_EQ(src_addr, srcstr.substr(1));
				EXPECT_EQ(dest_addr, dststr);				
			}

			string fdtuple = evt->get_param_value_str("tuple");
			string fdaddrs = fdtuple.substr(0, fdtuple.find(" "));
			string fdfile = fdtuple.substr(fdtuple.find(" ") + 1);

			EXPECT_EQ(NAME, fdfile);

			StringTokenizer fdtst(fdaddrs, ">");
			EXPECT_EQ(2, (int)fdtst.count());
			string fdsrcstr = fdtst[0].substr(0, fdtst[0].size() - 1);
			string fddststr = fdtst[1];

			EXPECT_EQ('u', fdsrcstr[0]);

			EXPECT_NE("u0000000000000000", fdsrcstr);
			EXPECT_NE("u0000000000000000", fddststr);

			callnum++;
		}

		if(callnum < 1)
		{
			return;
		}

		//
		// 32bit uses send() and recv(), while 64bit always uses sendto() and
		// recvfrom() and sets the address to NULL
		//
#ifdef __i386__
		if(evt->get_type() == PPME_SOCKET_SEND_E ||
		        evt->get_type() == PPME_SOCKET_RECV_E)
#else
		if(evt->get_type() == PPME_SOCKET_SENDTO_E ||
		        evt->get_type() == PPME_SOCKET_RECVFROM_E)
#endif
		{
#ifndef __i386__
			if(evt->get_param_value_str("tuple") != "")
			{
				EXPECT_EQ("NULL", evt->get_param_value_str("tuple"));
			}
#endif

			string fdtuple = evt->get_param_value_str("fd");
			string fdaddrs = fdtuple.substr(0, fdtuple.find(" "));
			string fdfile = fdtuple.substr(fdtuple.find(" ") + 1);

			EXPECT_EQ(NAME, fdfile);

			StringTokenizer fdtst(fdaddrs, ">");
			EXPECT_EQ(2, (int)fdtst.count());
			string fdsrcstr = fdtst[0].substr(0, fdtst[0].size() - 1);
			string fddststr = fdtst[1];

			EXPECT_EQ('u', fdsrcstr[0]);

			EXPECT_NE("u0", fdsrcstr);
			EXPECT_NE("0", fddststr);

			callnum++;
		}
#ifdef __i386__
		else if(evt->get_type() == PPME_SOCKET_RECV_X)
#else
		else if(evt->get_type() == PPME_SOCKET_RECVFROM_X)
#endif
		{
#ifndef __i386__
			EXPECT_EQ("NULL", evt->get_param_value_str("tuple"));
#endif
			EXPECT_EQ(PAYLOAD, evt->get_param_value_str("data"));

			callnum++;
		}

		if(PPME_SYSCALL_CLOSE_X == evt->get_type() && 0 == state && ends_with(evt->get_thread_info(false)->m_args[0], "unix_server.py"))
		{
			state = 1;
			sinsp_threadinfo* ti = evt->get_thread_info();
			ASSERT_EQ(1, (int)ti->m_ainfo->m_transaction_metrics.m_counter.m_count_in);
		}

	};


	//
	// OUTPUT VALDATION
	//
	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	EXPECT_FALSE(first_connect_or_accept_seen);
	EXPECT_EQ(8, callnum);
	EXPECT_EQ(1, state);
}

TEST_F(sys_call_test, DISABLED_unix_client_server_with_server_starting_before_capturing_starts)
{
	int state = 0;
	string sport;

	string src_addr;
	string dest_addr;

	proc server_proc("python", args() << "resources/unix_server.py");
	tuple<Poco::ProcessHandle, Poco::Pipe *> server = start_process(&server_proc);
	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		sinsp_threadinfo *info = evt->get_thread_info(false);
		return ends_with(info->get_comm(), "unix_server.py") || ends_with(info->get_comm(), "unix_client.py");
	};

	//
	// INITIALIZATION
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		process_list_t procs;
		procs.push_back(proc("python", args() << "resources/unix_client.py"));
		run_processes(procs);
		get<0>(server).wait();
	};

	//
	// OUTPUT VALIDATION
	//
	captured_event_callback_t callback = [&](const callback_param & param)
	{
		sinsp_evt *evt = param.m_evt;
		if(PPME_SYSCALL_CLOSE_X == evt->get_type() && 0 == state && ends_with(evt->get_thread_info(false)->get_comm(), "unix_server.py"))
		{
			state = 1;
			ASSERT_EQ(1, (int)param.m_inspector->get_transactions()->m_table[evt->get_tid()].size());
		}
	};


	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	//  EXPECT_EQ(8, callnum);
	EXPECT_EQ(1, state);
}

TEST_F(sys_call_test, DISABLED_unix_client_server_with_connection_before_capturing_starts)
{
	Poco::Thread server_thread;
	Poco::Thread client_thread;
	unix_server server;
	unix_client client;
	Poco::RunnableAdapter<unix_server> server_runnable(server, &unix_server::run);
	Poco::RunnableAdapter<unix_client> client_runnable(client, &unix_client::run);
	int state = 0;
	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return evt->get_tid() == server.get_tid() || evt->get_tid() == client.get_tid();
	};

	//
	// INITIALIZATION
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		server.signal_continue();
		client.signal_continue();
		server_thread.join();
		client_thread.join();
	};

	//
	// OUTPUT VALIDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt *evt = param.m_evt;
		if(PPME_SYSCALL_CLOSE_X == evt->get_type() && evt->get_tid() == server.get_tid())
		{
			state = 1;
			ASSERT_EQ(1, (int)param.m_inspector->get_transactions()->m_table[evt->get_tid()].size());
		}
	};

	server_thread.start(server_runnable);
	server.wait_for_server_ready();
	client_thread.start(client_runnable);
	client.wait_for_client_ready();

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	ASSERT_EQ(1, state);

}

