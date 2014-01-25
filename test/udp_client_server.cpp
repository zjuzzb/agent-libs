#define VISIBILITY_PRIVATE

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
#include <gtest.h>
#include <sys/syscall.h>
#include <Poco/NumberParser.h>


//#define __STDC_FORMAT_MACROS
//#include <inttypes.h>

using Poco::StringTokenizer;
using Poco::NumberParser;

#include "sinsp_int.h"
#include "analyzer_thread.h"

#define SERVER_PORT     3555
#define SERVER_PORT_STR "3555"
#define PAYLOAD         "0123456789QWERTYUIOPASDFGHJKLZXCVBNM"
#define BUFFER_LENGTH    (sizeof(PAYLOAD) - 1)
#define FALSE           0
#define NTRANSACTIONS   2

class udp_server
{
public:
	udp_server(bool use_unix, bool use_sendmsg)
	{
		m_use_unix = use_unix;
		m_use_sendmsg = use_sendmsg;
	}

	void run()
	{
		int sd = -1, rc;
		char buffer[BUFFER_LENGTH];
		struct sockaddr_in serveraddr;
		struct sockaddr_in clientaddr;
		socklen_t clientaddrlen = sizeof(clientaddr);
		int j;
		int domain;

		m_tid = syscall(SYS_gettid);

		if(m_use_unix)
		{
			domain = AF_UNIX;
		}
		else
		{
			domain = AF_INET;
		}

		do
		{
			sd = socket(domain, SOCK_DGRAM, 0);
			if(sd < 0)
			{
				perror("socket() failed");
				break;
			}

			memset(&serveraddr, 0, sizeof(serveraddr));
			serveraddr.sin_family = domain;
			serveraddr.sin_port = htons(SERVER_PORT);
			serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);

			rc = ::bind(sd, (struct sockaddr *) &serveraddr, sizeof(serveraddr));
			if(rc < 0)
			{
				perror("bind() failed");
				break;
			}

			m_server_ready.set();

			for(j = 0; j < NTRANSACTIONS; j++)
			{
				if(m_use_sendmsg)
				{
					struct msghdr msg;
					struct iovec iov;

					msg.msg_name = &clientaddr;
					msg.msg_namelen = clientaddrlen;
					msg.msg_iov = &iov;
					msg.msg_iovlen = 1;
					msg.msg_iov->iov_base = buffer;
					msg.msg_iov->iov_len = sizeof(buffer);
					msg.msg_control = 0;
					msg.msg_controllen = 0;
					msg.msg_flags = 0;

					//
					// Receive the data
					//
					recvmsg(sd, &msg, 0);

					//
					// Echo the data back to the client
					//
					if(sendmsg(sd, &msg, 0) == -1)
					{
						perror("sendmsg() failed");
						break;
					}
				}
				else
				{
					//
					// Receive the data
					//
					rc = recvfrom(sd, buffer, sizeof(buffer), 0,
					              (struct sockaddr *) &clientaddr,
					              &clientaddrlen);
					if(rc < 0)
					{
						perror("recvfrom() failed");
						break;
					}

					//
					// Echo the data back to the client
					//
					rc = sendto(sd, buffer, sizeof(buffer), 0,
					            (struct sockaddr *) &clientaddr,
					            sizeof(clientaddr));
					if(rc < 0)
					{
						FAIL();
						perror("sendto() failed");
						break;
					}
				}
			}
		}
		while(FALSE);

		if(sd != -1)
			close(sd);
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
	bool m_use_unix;
	bool m_use_sendmsg;
};

class udp_client
{
public:
	udp_client(uint32_t server_ip_address, bool use_connect)
	{
		m_use_unix = false;
		m_server_ip_address = server_ip_address;
		m_use_connect = use_connect;
	}

	void run()
	{
		int sd, rc;
		char buffer[BUFFER_LENGTH];
		struct sockaddr_in serveraddr;
		socklen_t serveraddrlen = sizeof(serveraddr);
		int j;
		int domain;

		if(m_use_unix)
		{
			domain = AF_UNIX;
		}
		else
		{
			domain = AF_INET;
		}

		sd = socket(domain, SOCK_DGRAM, 0);
		if(sd < 0)
		{
			FAIL();
		}

		memset(&serveraddr, 0, sizeof(serveraddr));
		serveraddr.sin_family = domain;
		serveraddr.sin_port = htons(SERVER_PORT);
		serveraddr.sin_addr.s_addr = m_server_ip_address;

		if(m_use_connect)
		{
			if(connect(sd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0)
			{
				close(sd);
				FAIL() << "connect() failed";
			}
		}

		memset(buffer, 0, sizeof(buffer));
		strncpy(buffer, PAYLOAD, sizeof(buffer));



		for(j = 0; j < NTRANSACTIONS; j++)
		{
			if(m_use_connect)
			{
				rc = sendto(sd, buffer, sizeof(buffer), 0, NULL, 0);
			}
			else
			{
				rc = sendto(sd, buffer, sizeof(buffer), 0,
				            (struct sockaddr *) &serveraddr,
				            sizeof(serveraddr));
			}
			if(rc < 0)
			{
				close(sd);
				FAIL();
			}

			//
			// Use the recvfrom() function to receive the data back from the
			// server.
			//
			rc = recvfrom(sd, buffer, sizeof(buffer), 0,
			              (struct sockaddr *) &serveraddr,
			              & serveraddrlen);
			if(rc < 0)
			{
				close(sd);
				FAIL();
			}
		}

		if(sd != -1)
		{
			close(sd);
		}
	}

private:
	bool m_use_unix;
	uint32_t m_server_ip_address;
	bool m_use_connect;
};

TEST_F(sys_call_test, udp_client_server)
{
	Poco::Thread server_thread;
	udp_server server(false, false);
	int32_t state = 0;
	int64_t fd_server_socket = 0;
	uint32_t server_ip_address = get_server_address();
	struct in_addr server_in_addr;
	server_in_addr.s_addr = get_server_address();
	char *server_address = inet_ntoa(server_in_addr);


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
		Poco::RunnableAdapter<udp_server> runnable(server, &udp_server::run);
		server_thread.start(runnable);
		server.wait_for_server_ready();

		udp_client client(server_ip_address, false);
		client.run();
		server_thread.join();
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();
		if(type == PPME_SYSCALL_CLOSE_X && e->get_tid() == server.get_tid())
		{
			sinsp_threadinfo* ti = e->get_thread_info();
			ASSERT_EQ(2, (int)ti->m_ainfo->m_transaction_metrics.m_counter.m_count_in);
		}

		if(type == PPME_SOCKET_RECVFROM_E)
		{
			fd_server_socket = *(int64_t *)e->get_param(0)->m_val;
		}
		switch(state)
		{
		case 0:
			EXPECT_NE(PPME_SOCKET_SENDTO_X, type);
			EXPECT_NE(PPME_SOCKET_RECVFROM_X, type);

			if(type == PPME_SOCKET_SENDTO_E)
			{
				StringTokenizer tst(e->get_param_value_str("tuple"), ">");
				EXPECT_EQ(2, (int)tst.count());

				string srcstr = tst[0].substr(0, tst[0].size() - 1);
				string dststr = tst[1];

				StringTokenizer sst(srcstr, ":");
				EXPECT_EQ(2, (int)sst.count());
				EXPECT_EQ("40.0.0.0", sst[0]);

				StringTokenizer dst(dststr, ":");
				EXPECT_EQ(2, (int)dst.count());
				EXPECT_EQ(server_address, dst[0]);
				EXPECT_EQ(SERVER_PORT_STR, dst[1]);

				state++;
			}
			break;
		case 1:
			if(type == PPME_SOCKET_RECVFROM_X)
			{
				StringTokenizer tst(e->get_param_value_str("tuple"), ">");
				EXPECT_EQ(2, (int)tst.count());

				string srcstr = tst[0].substr(0, tst[0].size() - 1);
				string dststr = tst[1];

				StringTokenizer sst(srcstr, ":");
				EXPECT_EQ(2, (int)sst.count());
				EXPECT_TRUE('4' == sst[0].c_str()[0]);
				EXPECT_STREQ(server_address, &sst[0].c_str()[1]);
				EXPECT_NE("0", sst[1]);

				StringTokenizer dst(dststr, ":");
				EXPECT_EQ(2, (int)dst.count());
				EXPECT_EQ("0.0.0.0", dst[0]);
				EXPECT_EQ(SERVER_PORT_STR, dst[1]);

				EXPECT_EQ(PAYLOAD, e->get_param_value_str("data"));
				sinsp_fdinfo_t *fdinfo = e->get_thread_info(false)->get_fd(fd_server_socket);
				EXPECT_EQ(server_ip_address, fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip);

				EXPECT_EQ(PAYLOAD, e->get_param_value_str("data"));

				state++;
			}
			break;
		case 2:
			EXPECT_NE(PPME_SOCKET_SENDTO_X, type);
			EXPECT_NE(PPME_SOCKET_RECVFROM_X, type);

			if(type == PPME_SOCKET_SENDTO_E)
			{
				StringTokenizer tst(e->get_param_value_str("tuple"), ">");
				EXPECT_EQ(2, (int)tst.count());

				string srcstr = tst[0].substr(0, tst[0].size() - 1);
				string dststr = tst[1];

				StringTokenizer sst(srcstr, ":");
				EXPECT_EQ(2, (int)sst.count());
				EXPECT_EQ("40.0.0.0", sst[0]);
				EXPECT_EQ(SERVER_PORT_STR, sst[1]);

				StringTokenizer dst(dststr, ":");
				EXPECT_EQ(2, (int)dst.count());
				EXPECT_EQ(server_address, dst[0]);
				EXPECT_NE("0", dst[1]);

//				EXPECT_EQ(PAYLOAD, e->get_param_value_str("data"));

				state++;
			}
			break;
		case 3:
			if(type == PPME_SOCKET_RECVFROM_X)
			{
				StringTokenizer tst(e->get_param_value_str("tuple"), ">");
				EXPECT_EQ(2, (int)tst.count());

				string srcstr = tst[0].substr(0, tst[0].size() - 1);
				string dststr = tst[1];

				StringTokenizer sst(srcstr, ":");
				EXPECT_EQ(2, (int)sst.count());
				EXPECT_TRUE('4' == sst[0].c_str()[0]);
				EXPECT_STREQ(server_address, &sst[0].c_str()[1]);
				EXPECT_EQ(SERVER_PORT_STR, sst[1]);

				StringTokenizer dst(dststr, ":");
				EXPECT_EQ(2, (int)dst.count());
				EXPECT_EQ("0.0.0.0", dst[0]);
				EXPECT_NE("0", dst[1]);

				EXPECT_EQ(PAYLOAD, e->get_param_value_str("data"));
				sinsp_fdinfo_t *fdinfo = e->get_thread_info(false)->get_fd(fd_server_socket);
				EXPECT_EQ(server_ip_address, fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip);

				state = 4;
			}
			break;
		case 4:
			break;
		default:
			FAIL();
			break;
		}
	};
	ASSERT_NO_FATAL_FAILURE( {event_capture::run(test, callback, filter);});
}

TEST_F(sys_call_test, udp_client_server_with_connect_by_client)
{
	Poco::Thread server_thread;
	udp_server server(false, false);
	uint32_t server_ip_address = get_server_address();
	struct in_addr server_in_addr;
	server_in_addr.s_addr = get_server_address();
	char *server_address = inet_ntoa(server_in_addr);
	int callnum = 0;
	string client_port;
	size_t transaction_count = 0;
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
		Poco::RunnableAdapter<udp_server> runnable(server, &udp_server::run);
		server_thread.start(runnable);
		server.wait_for_server_ready();

		udp_client client(server_ip_address, true);
		client.run();
		server_thread.join();
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();
		if(PPME_SOCKET_CONNECT_X == type)
		{
			StringTokenizer tst(e->get_param_value_str("tuple"), ">");
			EXPECT_EQ(2, (int)tst.count());

			string srcstr = tst[0].substr(0, tst[0].size() - 1);
			string dststr = tst[1];

			StringTokenizer sst(srcstr, ":");
			EXPECT_EQ(2, (int)sst.count());
			EXPECT_TRUE('4' == sst[0].c_str()[0]);
			EXPECT_STREQ(server_address, &sst[0].c_str()[1]);
			client_port = sst[1];

			StringTokenizer dst(dststr, ":");
			EXPECT_EQ(2, (int)dst.count());
			EXPECT_EQ(server_address, dst[0]);
			EXPECT_EQ(SERVER_PORT_STR, dst[1]);

			callnum++;
		}
		sinsp_threadinfo* ti = param.m_inspector->get_thread(server.get_tid(), false);
		if(ti)
		{
			transaction_count = (int)ti->m_ainfo->m_transaction_metrics.m_counter.m_count_in;
		}
	};
	ASSERT_NO_FATAL_FAILURE( {event_capture::run(test, callback, filter);});
	ASSERT_EQ(1, callnum);
	ASSERT_EQ((size_t)NTRANSACTIONS, transaction_count);
}

TEST_F(sys_call_test, udp_client_server_sendmsg)
{
	Poco::Thread server_thread;
	udp_server server(false, true);
	uint32_t server_ip_address = get_server_address();
	struct in_addr server_in_addr;
	server_in_addr.s_addr = get_server_address();
	char *server_address = inet_ntoa(server_in_addr);


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
		Poco::RunnableAdapter<udp_server> runnable(server, &udp_server::run);
		server_thread.start(runnable);
		server.wait_for_server_ready();

		udp_client client(server_ip_address, false);
		client.run();
		server_thread.join();
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_CLOSE_X && e->get_tid() == server.get_tid())
		{
			sinsp_threadinfo* ti = e->get_thread_info();
			ASSERT_EQ(2, (int)ti->m_ainfo->m_transaction_metrics.m_counter.m_count_in);
		}

		if(type == PPME_SOCKET_RECVMSG_X)
		{
			StringTokenizer tst(e->get_param_value_str("tuple"), ">");
			EXPECT_EQ(2, (int)tst.count());

			string srcstr = tst[0].substr(0, tst[0].size() - 1);
			string dststr = tst[1];

			StringTokenizer sst(srcstr, ":");
			EXPECT_EQ(2, (int)sst.count());
			EXPECT_TRUE('4' == sst[0].c_str()[0]);
			EXPECT_STREQ(server_address, &sst[0].c_str()[1]);
			EXPECT_NE("0", sst[1]);

			StringTokenizer dst(dststr, ":");
			EXPECT_EQ(2, (int)dst.count());
			EXPECT_EQ("0.0.0.0", dst[0]);
			EXPECT_EQ(SERVER_PORT_STR, dst[1]);

			EXPECT_EQ(PAYLOAD, e->get_param_value_str("data"));

			EXPECT_EQ(server_ip_address, e->m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip);
		}
		else if(type == PPME_SOCKET_SENDMSG_E)
		{
			StringTokenizer tst(e->get_param_value_str("tuple"), ">");
			EXPECT_EQ(2, (int)tst.count());

			string srcstr = tst[0].substr(0, tst[0].size() - 1);
			string dststr = tst[1];

			StringTokenizer sst(srcstr, ":");
			EXPECT_EQ(2, (int)sst.count());
			EXPECT_TRUE('4' == sst[0].c_str()[0]);
			EXPECT_STREQ(server_address, &sst[0].c_str()[1]);
			EXPECT_NE("0", sst[1]);

			StringTokenizer dst(dststr, ":");
			EXPECT_EQ(2, (int)dst.count());
			EXPECT_EQ("0.0.0.0", dst[0]);
			EXPECT_EQ(SERVER_PORT_STR, dst[1]);
			EXPECT_EQ((int)BUFFER_LENGTH, (int)NumberParser::parse(e->get_param_value_str("size")));
		}
		else if(type == PPME_SOCKET_SENDMSG_X)
		{
			EXPECT_EQ(PAYLOAD, e->get_param_value_str("data"));
		}
	};

	ASSERT_NO_FATAL_FAILURE( {event_capture::run(test, callback, filter);});
}
