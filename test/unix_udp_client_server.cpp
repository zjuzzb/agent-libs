#include "sys_call_test.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <netdb.h>
#include <Poco/RunnableAdapter.h>
#include <Poco/Thread.h>
#include <Poco/StringTokenizer.h>
#include <Poco/NumberFormatter.h>
#include <gtest.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>

//#define __STDC_FORMAT_MACROS
//#include <inttypes.h>

using Poco::StringTokenizer;
using Poco::NumberFormatter;

#define NAME "/tmp/python_unix_udp_sockets_example"
#define PAYLOAD "0123456789QWERTYUIOPASDFGHJKLZXCVBNM"

class unix_udp_server
{
public:
	unix_udp_server(bool use_recvfrom)
	{
		m_use_recvfrom = use_recvfrom;
	}

	void run()
	{
		int sock;
		struct sockaddr_un name;
		struct sockaddr_un caddr;
		socklen_t address_length = sizeof(struct sockaddr_un);
		char buf[1024];
		
		m_tid = syscall(SYS_gettid);		

		/* Create socket from which to read. */
		sock = socket(AF_UNIX, SOCK_DGRAM, 0);
		if (sock < 0) {
			perror("opening datagram socket");
			exit(1);
		}

		/* Create name. */
		name.sun_family = AF_UNIX;
		strcpy(name.sun_path, NAME);

		if (::bind(sock, (struct sockaddr *)&name, SUN_LEN(&name))) {
			perror("binding name to datagram socket");
			exit(1);
		}

		m_server_ready.set();

		/* Read from the socket. */
		if(m_use_recvfrom)
		{
			recvfrom(sock, buf, 1024, 0,
	                 (struct sockaddr*)&caddr, &address_length);

			recvfrom(sock, buf, 1024, 0,
	                 (struct sockaddr*)&caddr, &address_length);			
		}
		else
		{
			read(sock, buf, 1024);

			read(sock, buf, 1024);
		}

		close(sock);

		unlink(NAME);

	}

	void wait_for_server_ready()
	{
		m_server_ready.wait();
	}

	int64_t get_tid()
	{
		return m_tid;
	}

private:
	Poco::Event m_server_ready;
	int64_t m_tid;
	bool m_use_recvfrom;
};

class unix_udp_client
{
public:
	void run()
	{
		int sock;
		struct sockaddr_un name;

		/* Create socket on which to send. */
		sock = socket(AF_UNIX, SOCK_DGRAM, 0);
		if (sock < 0) {
			perror("opening datagram socket");
			exit(1);
		}

		/* Construct name of socket to send to. */
		name.sun_family = AF_UNIX;
		strcpy(name.sun_path, NAME);
		/* Send message. */

		sendto(sock, PAYLOAD, sizeof(PAYLOAD) - 1, 0, (struct sockaddr *)&name,
			sizeof(struct sockaddr_un));

		sendto(sock, PAYLOAD, sizeof(PAYLOAD) - 1, 0, (struct sockaddr *)&name,
			sizeof(struct sockaddr_un));

		close(sock); 
	}

private:
};

TEST_F(sys_call_test, unix_udp_client_server)
{
	Poco::Thread server_thread;
	unix_udp_server server(true);
	int32_t callnum = 0;
	string sport;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return evt->get_tid() == server.get_tid() || m_tid_filter(evt);
	};

	//
	// INITIALIZATION
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		Poco::RunnableAdapter<unix_udp_server> runnable(server, &unix_udp_server::run);
		server_thread.start(runnable);
		server.wait_for_server_ready();

		unix_udp_client client;
		client.run();
		server_thread.join();
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{

		sinsp_evt* evt = param.m_evt;
		if(evt->get_type() == PPME_SOCKET_BIND_X)
		{
			string ttuple = evt->get_param_value_str("addr");
			string ttype = ttuple.substr(0, ttuple.find(" "));
			string tfile = ttuple.substr(ttuple.find(" ") + 1);

			EXPECT_EQ("u", ttype);
			EXPECT_EQ(NAME, tfile);

			callnum++;
		}

		if(evt->get_type() == PPME_SOCKET_SENDTO_E ||
		    evt->get_type() == PPME_SOCKET_RECVFROM_X)
		{
			string ttuple = evt->get_param_value_str("tuple");
			string taddrs = ttuple.substr(0, ttuple.find(" "));
			string tfile = ttuple.substr(ttuple.find(" ") + 1);

			EXPECT_EQ(NAME, tfile);

			StringTokenizer ttst(taddrs, ">");
			EXPECT_EQ(2, (int)ttst.count());
			string tsrcstr = ttst[0].substr(0, ttst[0].size() - 1);
			string tdststr = ttst[1];

			EXPECT_EQ('u', tsrcstr[0]);

			if(evt->get_tid() == server.get_tid())
			{
				EXPECT_NE("u0", tsrcstr);
				EXPECT_EQ("0", tdststr);
			}
			else
			{
				EXPECT_EQ("u0", tsrcstr);
				EXPECT_NE("0", tdststr);
			}

			string fdtuple = evt->get_param_value_str("fd");

			if(fdtuple.length() > 1)
			{
				string fdaddrs = fdtuple.substr(0, fdtuple.find(" "));
				string fdfile = fdtuple.substr(fdtuple.find(" ") + 1);

				EXPECT_EQ(NAME, fdfile);

				StringTokenizer fdtst(fdaddrs, ">");
				EXPECT_EQ(2, (int)fdtst.count());
				string fdsrcstr = fdtst[0].substr(0, fdtst[0].size() - 1);
				string fddststr = fdtst[1];

				EXPECT_EQ('u', fdsrcstr[0]);

				EXPECT_EQ("u0", fdsrcstr);
				EXPECT_NE("0", fddststr);
			}
			else
			{
				if(fdtuple.length() == 1)
				{
					EXPECT_EQ("u", fdtuple);					
				}
			}

			if(evt->get_type() == PPME_SOCKET_SENDTO_X)
			{
				EXPECT_EQ(PAYLOAD, evt->get_param_value_str("data"));
			}


			callnum++;
		}
		else if(evt->get_type() == PPME_SOCKET_RECVFROM_X)
		{
			EXPECT_EQ("NULL", evt->get_param_value_str("tuple"));
			EXPECT_EQ(PAYLOAD, evt->get_param_value_str("data"));

			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE( { event_capture::run(test, callback, filter);});
	EXPECT_EQ(5, callnum);
}

TEST_F(sys_call_test, unix_udp_client_server_read)
{
	Poco::Thread server_thread;
	unix_udp_server server(false);
	int32_t callnum = 0;
	string sport;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return evt->get_tid() == server.get_tid() || m_tid_filter(evt);
	};

	//
	// INITIALIZATION
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		Poco::RunnableAdapter<unix_udp_server> runnable(server, &unix_udp_server::run);
		server_thread.start(runnable);
		server.wait_for_server_ready();

		unix_udp_client client;
		client.run();
		server_thread.join();
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{

		sinsp_evt* evt = param.m_evt;
		if(evt->get_type() == PPME_SOCKET_BIND_X)
		{
			string ttuple = evt->get_param_value_str("addr");
			string ttype = ttuple.substr(0, ttuple.find(" "));
			string tfile = ttuple.substr(ttuple.find(" ") + 1);

			EXPECT_EQ("u", ttype);
			EXPECT_EQ(NAME, tfile);

			callnum++;
		}

		if(evt->get_type() == PPME_SOCKET_SENDTO_E)
		{
			string ttuple = evt->get_param_value_str("tuple");
			string taddrs = ttuple.substr(0, ttuple.find(" "));
			string tfile = ttuple.substr(ttuple.find(" ") + 1);

			EXPECT_EQ(NAME, tfile);

			StringTokenizer ttst(taddrs, ">");
			EXPECT_EQ(2, (int)ttst.count());
			string tsrcstr = ttst[0].substr(0, ttst[0].size() - 1);
			string tdststr = ttst[1];

			EXPECT_EQ('u', tsrcstr[0]);

			if(evt->get_tid() == server.get_tid())
			{
				EXPECT_NE("u0", tsrcstr);
				EXPECT_EQ("0", tdststr);
			}
			else
			{
				EXPECT_EQ("u0", tsrcstr);
				EXPECT_NE("0", tdststr);
			}

			string fdtuple = evt->get_param_value_str("fd");

			if(fdtuple.length() > 1)
			{
				string fdaddrs = fdtuple.substr(0, fdtuple.find(" "));
				string fdfile = fdtuple.substr(fdtuple.find(" ") + 1);

				EXPECT_EQ(NAME, fdfile);

				StringTokenizer fdtst(fdaddrs, ">");
				EXPECT_EQ(2, (int)fdtst.count());
				string fdsrcstr = fdtst[0].substr(0, fdtst[0].size() - 1);
				string fddststr = fdtst[1];

				EXPECT_EQ('u', fdsrcstr[0]);

				if(evt->get_tid() == server.get_tid())
				{
					EXPECT_NE("u0", tsrcstr);
					EXPECT_EQ("0", tdststr);
				}
				else
				{
					EXPECT_EQ("u0", tsrcstr);
					EXPECT_NE("0", tdststr);
				}
			}
			else
			{
				if(fdtuple.length() == 1)
				{
					EXPECT_EQ("u", fdtuple);					
				}
			}

			if(evt->get_type() == PPME_SOCKET_SENDTO_X)
			{
				EXPECT_EQ(PAYLOAD, evt->get_param_value_str("data"));
			}


			callnum++;
		}
		else if(evt->get_type() == PPME_SYSCALL_READ_E)
		{
			if(callnum < 1)
			{
				return;
			}

			string fdtuple = evt->get_param_value_str("fd");

			EXPECT_GT(fdtuple.length(), (unsigned int)1);

			if(fdtuple.length() > 1)
			{
				string ttype = fdtuple.substr(0, fdtuple.find(" "));
				string tfile = fdtuple.substr(fdtuple.find(" ") + 1);

				EXPECT_EQ("u", ttype);
				EXPECT_EQ(NAME, tfile);
			}

			callnum++;
		}
		else if(evt->get_type() == PPME_SYSCALL_READ_X)
		{
			EXPECT_EQ(PAYLOAD, evt->get_param_value_str("data"));

			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE( { event_capture::run(test, callback, filter);});
	EXPECT_EQ(7, callnum);
}
