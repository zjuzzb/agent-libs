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
	udp_server(bool use_unix, bool use_sendmsg, bool recvmsg_twobufs, uint32_t port_offset=0)
	{
		m_use_unix = use_unix;
		m_use_sendmsg = use_sendmsg;
		m_recvmsg_twobufs = recvmsg_twobufs;
		m_port = SERVER_PORT + port_offset;
	}

	void run()
	{
		int sd = -1, rc;
		char buffer[BUFFER_LENGTH + 10];
		char buffer1[BUFFER_LENGTH - 10];
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
			serveraddr.sin_port = htons(m_port);
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
					struct iovec iov[2];

					if(m_recvmsg_twobufs)
					{
						iov[0].iov_base = buffer1;
						iov[0].iov_len = BUFFER_LENGTH - 10;
						iov[1].iov_base = buffer;
						iov[1].iov_len = BUFFER_LENGTH - 10;

						msg.msg_name = &clientaddr;
						msg.msg_namelen = clientaddrlen;
						msg.msg_iov = iov;
						msg.msg_iovlen = 2;
						msg.msg_control = 0;
						msg.msg_controllen = 0;
						msg.msg_flags = 0;

						//
						// Receive the data
						//
						int res = recvmsg(sd, &msg, 0);
						EXPECT_EQ(res, (int)BUFFER_LENGTH);

						//
						// Set the send buffer
						//
						iov[0].iov_len = BUFFER_LENGTH - 10;
						iov[1].iov_len = 10;
					}
					else
					{
						iov[0].iov_base = buffer;
						iov[0].iov_len = BUFFER_LENGTH + 10;

						msg.msg_name = &clientaddr;
						msg.msg_namelen = clientaddrlen;
						msg.msg_iov = iov;
						msg.msg_iovlen = 1;
						msg.msg_control = 0;
						msg.msg_controllen = 0;
						msg.msg_flags = 0;

						//
						// Receive the data
						//
						int res = recvmsg(sd, &msg, 0);
						EXPECT_EQ(res, (int)BUFFER_LENGTH);

						//
						// Set the send buffer
						//
						iov[0].iov_len = BUFFER_LENGTH;
					}

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
	bool m_recvmsg_twobufs;
	uint16_t m_port;
};

class udp_client
{
public:
	udp_client(uint32_t server_ip_address, bool use_connect, uint16_t base_port = SERVER_PORT, uint32_t num_servers = 1):
			m_use_sendmsg(false),
			m_recv(true),
			m_payload(PAYLOAD),
			m_ignore_errors(false),
			m_n_transactions(NTRANSACTIONS)
	{
		m_use_unix = false;
		m_server_ip_address = server_ip_address;
		m_use_connect = use_connect;
		for (uint32_t idx = 0; idx < num_servers; idx++)
		{
			m_server_ports.push_back(base_port+idx);
		}
	}

	void run()
	{
		int sd;
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

		for(auto port : m_server_ports)
		{
			run_using_port(sd, domain, port);
		}

		if(sd != -1)
		{
			close(sd);
		}
	}

	void run_using_port(int sd, int domain, uint16_t port)
	{
		int rc;
		int j;
		struct sockaddr_in serveraddr;
		socklen_t serveraddrlen = sizeof(serveraddr);

		memset(&serveraddr, 0, sizeof(serveraddr));
		serveraddr.sin_family = domain;
		serveraddr.sin_port = htons(port);
		serveraddr.sin_addr.s_addr = m_server_ip_address;

		if(m_use_connect)
		{
			if(connect(sd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0 && !m_ignore_errors)
			{
				close(sd);
				FAIL() << "connect() failed";
			}
		}

		for(j = 0; j < m_n_transactions; j++)
		{
			if(!m_use_sendmsg)
			{
				if(m_use_connect)
				{
					rc = sendto(sd, m_payload.data(), m_payload.size(), 0, NULL, 0);
				}
				else
				{
					rc = sendto(sd, m_payload.data(), m_payload.size(), 0,
								(struct sockaddr *) &serveraddr,
								sizeof(serveraddr));
				}
			}
			else
			{
				struct msghdr msg = { 0 };
				if(m_use_connect)
				{
					msg.msg_name = NULL;
				}
				else
				{
					msg.msg_name = (void*) &serveraddr;
					msg.msg_namelen = sizeof(serveraddr);
				}
				struct iovec iov;
				iov.iov_base = (void*)m_payload.data();
				iov.iov_len = m_payload.size();
				msg.msg_iov = &iov;
				msg.msg_iovlen = 1;
				rc = sendmsg(sd, &msg, MSG_DONTWAIT);
			}
			if(rc < 0 && !m_ignore_errors)
			{
				close(sd);
				FAIL();
			}

			//
			// Use the recvfrom() function to receive the data back from the
			// server.
			//
			if(m_recv)
			{
				char* buffer = (char*) malloc(m_payload.size());
				rc = recvfrom(sd, buffer, m_payload.size(), 0,
							  (struct sockaddr *) &serveraddr,
							  & serveraddrlen);
				free(buffer);
				if(rc < 0 && !m_ignore_errors)
				{
					close(sd);
					FAIL();
				}
			}
		}
	}

	bool m_use_sendmsg;
	bool m_recv;
	string m_payload;
	bool m_use_connect;
	bool m_ignore_errors;
	int m_n_transactions;
private:
	bool m_use_unix;
	uint32_t m_server_ip_address;
	std::vector<uint16_t> m_server_ports;
};

class udp_servers_and_client
{
public:
	udp_servers_and_client(bool use_unix, bool use_sendmsg, bool recvmsg_twobufs, bool use_connect, uint32_t num_servers)
	{
		m_server_ip_address = get_server_address();
		struct in_addr server_in_addr;
		server_in_addr.s_addr = m_server_ip_address;
		m_server_address = inet_ntoa(server_in_addr);
		m_use_connect = use_connect;

		for(uint32_t idx = 0; idx < num_servers; idx++)
		{
			m_server_ports.set(SERVER_PORT + idx);
			m_threads.emplace_back(std::make_shared<Poco::Thread>());
			m_servers.emplace_back(std::make_shared<udp_server>(use_unix, use_sendmsg, recvmsg_twobufs, idx));
		}
	}

	uint32_t server_ip_address()
	{
		return m_server_ip_address;
	}

	std::string &server_address()
	{
		return m_server_address;
	}

	bool is_server_tid(int64_t tid)
	{
		for(auto &srv : m_servers)
		{
			if(tid == srv->get_tid())
			{
				return true;
			}
		}

		return false;
	}

	std::vector<std::shared_ptr<udp_server>> &get_servers()
	{
		return m_servers;
	}

	bool is_server_port(std::string &portstr)
	{
		uint16_t port = std::stoi(portstr);

		return (port >= SERVER_PORT &&
			port < SERVER_PORT+m_servers.size());
	}

	bool filter(sinsp_evt *evt)
	{
		return is_server_tid(evt->get_tid());
	}

	ports_set &server_ports()
	{
		return m_server_ports;
	}

	void start()
	{
		for(uint32_t idx = 0; idx < m_servers.size(); idx++)
		{
			Poco::RunnableAdapter<udp_server> runnable(*(m_servers[idx]), &udp_server::run);
			m_threads[idx]->start(runnable);
			m_servers[idx]->wait_for_server_ready();
		}

		udp_client client(m_server_ip_address, m_use_connect, SERVER_PORT, m_servers.size());
		client.run();

		for(auto &thread : m_threads)
		{
			thread->join();
		}
	}

private:
	uint32_t m_server_ip_address;
	std::string m_server_address;
	std::vector<std::shared_ptr<Poco::Thread>> m_threads;
	std::vector<std::shared_ptr<udp_server>> m_servers;
	ports_set m_server_ports;
	bool m_use_connect;
};


TEST_F(sys_call_test, udp_client_server)
{
	int32_t state = 0;
	bool use_unix=false, use_sendmsg=false, recvmsg_twobufs=false, use_connect=false;
	uint32_t num_servers = 1;
	udp_servers_and_client udps(use_unix, use_sendmsg, recvmsg_twobufs, use_connect, num_servers);
	int64_t fd_server_socket = 0;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return udps.filter(evt) || m_tid_filter(evt);
	};

	//
	// INITIALIZATION
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		udps.start();
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();
		if(type == PPME_SYSCALL_CLOSE_X && udps.is_server_tid(e->get_tid()))
		{
			sinsp_threadinfo* ti = e->get_thread_info();
			ASSERT_EQ((uint64_t) 2, ti->m_ainfo->m_transaction_metrics.get_counter()->m_count_in);
			ASSERT_NE((uint64_t) 0, ti->m_ainfo->m_transaction_metrics.get_counter()->m_time_ns_in);
			ASSERT_EQ((uint64_t) 1, ti->m_ainfo->m_transaction_metrics.get_max_counter()->m_count_in);
			ASSERT_NE((uint64_t) 0, ti->m_ainfo->m_transaction_metrics.get_max_counter()->m_time_ns_in);
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
				EXPECT_EQ("0.0.0.0", sst[0]);

				StringTokenizer dst(dststr, ":");
				EXPECT_EQ(2, (int)dst.count());
				EXPECT_EQ(udps.server_address(), dst[0]);
				EXPECT_TRUE(udps.is_server_port(dst[1]));

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
				EXPECT_EQ(udps.server_address(), sst[0]);
				EXPECT_NE("0", sst[1]);

				StringTokenizer dst(dststr, ":");
				EXPECT_EQ(2, (int)dst.count());
				EXPECT_EQ("0.0.0.0", dst[0]);
				EXPECT_TRUE(udps.is_server_port(dst[1]));

				EXPECT_EQ(PAYLOAD, e->get_param_value_str("data"));
				sinsp_fdinfo_t *fdinfo = e->get_thread_info(false)->get_fd(fd_server_socket);
				ASSERT_TRUE(fdinfo);
				EXPECT_EQ(udps.server_ip_address(), fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip);

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
				EXPECT_EQ("0.0.0.0", sst[0]);
				EXPECT_TRUE(udps.is_server_port(sst[1]));

				StringTokenizer dst(dststr, ":");
				EXPECT_EQ(2, (int)dst.count());
				EXPECT_EQ(udps.server_address(), dst[0]);
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
				EXPECT_EQ(udps.server_address(), sst[0]);
				EXPECT_TRUE(udps.is_server_port(sst[1]));

				StringTokenizer dst(dststr, ":");
				EXPECT_EQ(2, (int)dst.count());
				EXPECT_EQ("0.0.0.0", dst[0]);
				EXPECT_NE("0", dst[1]);

				EXPECT_EQ(PAYLOAD, e->get_param_value_str("data"));
				sinsp_fdinfo_t *fdinfo = e->get_thread_info(false)->get_fd(fd_server_socket);
				ASSERT_TRUE(fdinfo);
				EXPECT_EQ(udps.server_ip_address(), fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip);

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

	sinsp_configuration configuration;
	configuration.set_known_ports(udps.server_ports());
	ASSERT_NO_FATAL_FAILURE( {event_capture::run(test, callback, filter, configuration);});
}

TEST_F(sys_call_test, udp_client_server_with_connect_by_client)
{
	bool use_unix=false, use_sendmsg=false, recvmsg_twobufs=false, use_connect=true;
	uint32_t num_servers = 1;
	udp_servers_and_client udps(use_unix, use_sendmsg, recvmsg_twobufs, use_connect, num_servers);

	int callnum = 0;
	string client_port;
	size_t transaction_count = 0;
	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return udps.filter(evt) || m_tid_filter(evt);
	};

	//
	// INITIALIZATION
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		udps.start();
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
			EXPECT_EQ(udps.server_address(), sst[0]);
			client_port = sst[1];

			StringTokenizer dst(dststr, ":");
			EXPECT_EQ(2, (int)dst.count());
			EXPECT_EQ(udps.server_address(), dst[0]);
			EXPECT_TRUE(udps.is_server_port(dst[1]));

			callnum++;
		}
		for (auto &srv : udps.get_servers())
		{
			sinsp_threadinfo* ti = param.m_inspector->get_thread(srv->get_tid(), false, true);
			if(ti)
			{
				transaction_count = ti->m_ainfo->m_transaction_metrics.get_counter()->m_count_in;
			}
		}
	};

	sinsp_configuration configuration;
	configuration.set_known_ports(udps.server_ports());
	ASSERT_NO_FATAL_FAILURE( {event_capture::run(test, callback, filter, configuration);});
	ASSERT_EQ(1, callnum);
	ASSERT_EQ((size_t)NTRANSACTIONS, transaction_count);
}

TEST_F(sys_call_test, udp_client_server_sendmsg)
{
	bool use_unix=false, use_sendmsg=true, recvmsg_twobufs=false, use_connect=false;
	uint32_t num_servers = 1;
	udp_servers_and_client udps(use_unix, use_sendmsg, recvmsg_twobufs, use_connect, num_servers);

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return udps.filter(evt) || m_tid_filter(evt);
	};

	//
	// INITIALIZATION
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		udps.start();
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_CLOSE_X && udps.is_server_tid(e->get_tid()))
		{
			sinsp_threadinfo* ti = e->get_thread_info();
			ASSERT_EQ((uint64_t) 2, ti->m_ainfo->m_transaction_metrics.get_counter()->m_count_in);
			ASSERT_NE((uint64_t) 0, ti->m_ainfo->m_transaction_metrics.get_counter()->m_time_ns_in);
			ASSERT_EQ((uint64_t) 1, ti->m_ainfo->m_transaction_metrics.get_max_counter()->m_count_in);
			ASSERT_NE((uint64_t) 0, ti->m_ainfo->m_transaction_metrics.get_max_counter()->m_time_ns_in);
		}

		if(type == PPME_SOCKET_RECVMSG_X)
		{
			StringTokenizer tst(e->get_param_value_str("tuple"), ">");
			EXPECT_EQ(2, (int)tst.count());

			string srcstr = tst[0].substr(0, tst[0].size() - 1);
			string dststr = tst[1];

			StringTokenizer sst(srcstr, ":");
			EXPECT_EQ(2, (int)sst.count());
			EXPECT_EQ(udps.server_address(), sst[0]);
			EXPECT_NE("0", sst[1]);

			StringTokenizer dst(dststr, ":");
			EXPECT_EQ(2, (int)dst.count());
			EXPECT_EQ("0.0.0.0", dst[0]);
			EXPECT_TRUE(udps.is_server_port(dst[1]));

			EXPECT_EQ(PAYLOAD, e->get_param_value_str("data"));

			EXPECT_EQ(udps.server_ip_address(), e->m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip);
		}
		else if(type == PPME_SOCKET_SENDMSG_E)
		{
			StringTokenizer tst(e->get_param_value_str("tuple"), ">");
			EXPECT_EQ(2, (int)tst.count());

			string srcstr = tst[0].substr(0, tst[0].size() - 1);
			string dststr = tst[1];

			StringTokenizer sst(srcstr, ":");
			EXPECT_EQ(2, (int)sst.count());
			EXPECT_STREQ("0.0.0.0", sst[0].c_str());
			EXPECT_TRUE(udps.is_server_port(sst[1]));

			StringTokenizer dst(dststr, ":");
			EXPECT_EQ(2, (int)dst.count());
			EXPECT_EQ(udps.server_address(), dst[0]);
			EXPECT_NE("0", dst[1]);
			EXPECT_EQ((int)BUFFER_LENGTH, (int)NumberParser::parse(e->get_param_value_str("size")));
		}
		else if(type == PPME_SOCKET_SENDMSG_X)
		{
			EXPECT_EQ(PAYLOAD, e->get_param_value_str("data"));
		}
	};

	sinsp_configuration configuration;
	configuration.set_known_ports(udps.server_ports());

	ASSERT_NO_FATAL_FAILURE( {event_capture::run(test, callback, filter, configuration);});
}

TEST_F(sys_call_test, udp_client_server_sendmsg_2buf)
{
	bool use_unix=false, use_sendmsg=true, recvmsg_twobufs=true, use_connect=false;
	uint32_t num_servers = 1;
	udp_servers_and_client udps(use_unix, use_sendmsg, recvmsg_twobufs, use_connect, num_servers);

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return udps.filter(evt) || m_tid_filter(evt);
	};

	//
	// INITIALIZATION
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		udps.start();
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_CLOSE_X && udps.is_server_tid(e->get_tid()))
		{
			sinsp_threadinfo* ti = e->get_thread_info();
			ASSERT_EQ((uint64_t) 2, ti->m_ainfo->m_transaction_metrics.get_counter()->m_count_in);
			ASSERT_NE((uint64_t) 0, ti->m_ainfo->m_transaction_metrics.get_counter()->m_time_ns_in);
			ASSERT_EQ((uint64_t) 1, ti->m_ainfo->m_transaction_metrics.get_max_counter()->m_count_in);
			ASSERT_NE((uint64_t) 0, ti->m_ainfo->m_transaction_metrics.get_max_counter()->m_time_ns_in);
		}

		if(type == PPME_SOCKET_RECVMSG_X)
		{
			StringTokenizer tst(e->get_param_value_str("tuple"), ">");
			EXPECT_EQ(2, (int)tst.count());

			string srcstr = tst[0].substr(0, tst[0].size() - 1);
			string dststr = tst[1];

			StringTokenizer sst(srcstr, ":");
			EXPECT_EQ(2, (int)sst.count());
			EXPECT_EQ(udps.server_address(), sst[0]);
			EXPECT_NE("0", sst[1]);

			StringTokenizer dst(dststr, ":");
			EXPECT_EQ(2, (int)dst.count());
			EXPECT_EQ("0.0.0.0", dst[0]);
			EXPECT_TRUE(udps.is_server_port(dst[1]));

			EXPECT_EQ(PAYLOAD, e->get_param_value_str("data"));

			EXPECT_EQ(udps.server_ip_address(), e->m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip);
		}
		else if(type == PPME_SOCKET_SENDMSG_E)
		{
			StringTokenizer tst(e->get_param_value_str("tuple"), ">");
			EXPECT_EQ(2, (int)tst.count());

			string srcstr = tst[0].substr(0, tst[0].size() - 1);
			string dststr = tst[1];

			StringTokenizer sst(srcstr, ":");
			EXPECT_EQ(2, (int)sst.count());
			EXPECT_STREQ("0.0.0.0", sst[0].c_str());
			EXPECT_TRUE(udps.is_server_port(sst[1]));

			StringTokenizer dst(dststr, ":");
			EXPECT_EQ(2, (int)dst.count());
			EXPECT_EQ(udps.server_address(), dst[0]);
			EXPECT_NE("0", dst[1]);
			EXPECT_EQ((int)BUFFER_LENGTH, (int)NumberParser::parse(e->get_param_value_str("size")));
		}
		else if(type == PPME_SOCKET_SENDMSG_X)
		{
			EXPECT_EQ(PAYLOAD, e->get_param_value_str("data"));
		}
	};

	sinsp_configuration configuration;
	configuration.set_known_ports(udps.server_ports());

	ASSERT_NO_FATAL_FAILURE( {event_capture::run(test, callback, filter, configuration);});
}

static void run_fd_name_changed_test(bool use_sendmsg, bool recvmsg_twobufs, bool use_connect,
				     event_filter_t m_tid_filter, uint32_t expected_name_changed_evts)
{
	bool use_unix=false;
	uint32_t num_servers = 2;
	udp_servers_and_client udps(use_unix, use_sendmsg, recvmsg_twobufs, use_connect, num_servers);

	sinsp_filter_compiler compiler(NULL, "fd.name_changed=true");
	unique_ptr<sinsp_filter> fd_name_changed(compiler.compile());

	uint32_t num_name_changed_evts = 0;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return udps.filter(evt) || m_tid_filter(evt);
	};

	//
	// INITIALIZATION
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		udps.start();
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		if(fd_name_changed->run(e))
		{
			num_name_changed_evts++;
		}
	};

	sinsp_configuration configuration;
	configuration.set_known_ports(udps.server_ports());

	ASSERT_NO_FATAL_FAILURE( {event_capture::run(test, callback, filter, configuration);});

	ASSERT_EQ(num_name_changed_evts, expected_name_changed_evts);
}

TEST_F(sys_call_test, udp_client_server_fd_name_changed)
{
	bool use_sendmsg=false, recvmsg_twobufs=false, use_connect=false;

	// This test only needs to count events. We want to
	// see 7 events, representing the following:
	//  - The servers bind()ing their sockets to their server ports.
	//  - the udp client sending to the first server.
	//  - the first udp server receiving from the udp client
	//  - the udp client receiving the echoed response from the first udp server.
	//    This results in an event, even though this fd has already
	//    been used between the server and client, because this
	//    recvfrom sets the client side port as a result of
	//    the recvfrom().
	//  - the udp client sending to the second server
	//  - the second udp server receiving from the udp client
	//
	// Events that do *not* trigger name_changed are:
	//  - the first/second udp server sending the echoed response to the udp client. This is because it's using
	//    the same client/server address + port as when it received the packet from the udp client.
	//  - the udp client receiving the second echo back from the second server. This is because
	//    the client side port was already set from the communication with the first server.

	run_fd_name_changed_test(use_sendmsg, recvmsg_twobufs, use_connect, m_tid_filter, 7);
}

TEST_F(sys_call_test, udp_client_server_connect_fd_name_changed)
{
	bool use_sendmsg=false, recvmsg_twobufs=false, use_connect=true;

	// When the client uses connect, there is one fewer name
	// changed event, as there is no name change when the client
	// receives the echoed response from the server.

	run_fd_name_changed_test(use_sendmsg, recvmsg_twobufs, use_connect, m_tid_filter, 6);
}

TEST_F(sys_call_test, udp_client_server_sendmsg_fd_name_changed)
{
	bool use_sendmsg=true, recvmsg_twobufs=false, use_connect=false;

	run_fd_name_changed_test(use_sendmsg, recvmsg_twobufs, use_connect, m_tid_filter, 7);
}

TEST_F(sys_call_test, udp_client_server_multiple_connect_name_changed)
{
	sinsp_filter_compiler compiler(NULL, "fd.name_changed=true");
	unique_ptr<sinsp_filter> fd_name_changed(compiler.compile());
	uint32_t num_name_changed_evts = 0;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return m_tid_filter(evt);
	};

	//
	// INITIALIZATION
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		int sd;

		sd = socket(AF_INET, SOCK_DGRAM, 0);
		if(sd < 0)
		{
			FAIL();
		}

		std::list<uint16_t> ports = {8172, 8193, 8193, 8172, 8171};

		for(auto &port : ports)
		{
			struct sockaddr_in serveraddr;

			memset(&serveraddr, 0, sizeof(serveraddr));
			serveraddr.sin_family = AF_INET;
			serveraddr.sin_port = htons(port);
			serveraddr.sin_addr.s_addr = get_server_address();

			if(connect(sd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0)
			{
				close(sd);
				FAIL() << "connect() failed";
			}
		}
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		if(fd_name_changed->run(e))
		{
			num_name_changed_evts++;
		}
	};

	sinsp_configuration configuration;
	ASSERT_NO_FATAL_FAILURE( {event_capture::run(test, callback, filter, configuration);});

	// Every connect should result in a name changed event other than the duplicate port.
	ASSERT_EQ(num_name_changed_evts, 4u);
}

TEST_F(sys_call_test, udp_client_server_sendmsg_2buf_fd_name_changed)
{
	bool use_sendmsg=true, recvmsg_twobufs=true, use_connect=false;

	run_fd_name_changed_test(use_sendmsg, recvmsg_twobufs, use_connect, m_tid_filter, 7);
}

TEST_F(sys_call_test, statsd_client_snaplen)
{
	// Test if the driver correctly increase snaplen for statsd traffic
	string payload = "soluta.necessitatibus.voluptatem.consequuntur.dignissimos.repudiandae.nostrum.lorem.ipsum:18|c";

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return m_tid_filter(evt) && ( evt->get_type() == PPME_SOCKET_SENDMSG_X || evt->get_type() == PPME_SOCKET_SENDTO_X);
	};

	//
	// INITIALIZATION
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		// sendto with addr
		udp_client client(0x0100007F, false, 8125);
		client.m_payload = payload;
		client.m_ignore_errors = true;
		client.m_recv = false;
		client.m_n_transactions = 1;
		client.run();

		// sendto without addr (connect)
		client.m_use_connect = true;
		client.run();

		// sendmsg with addr
		client.m_use_connect = false;
		client.m_use_sendmsg = true;
		client.run();

		// sendmsg without addr
		client.m_use_connect = true;
		client.run();
	};

	//
	// OUTPUT VALDATION
	//
	int n = 0;
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		++n;
		EXPECT_EQ(payload, e->get_param_value_str("data")) << "Failure on " << e->get_name() << " n=" << n;
	};

	ASSERT_NO_FATAL_FAILURE( {event_capture::run(test, callback, filter);});
	EXPECT_EQ(4, n);
}

TEST_F(sys_call_test, statsd_client_no_snaplen)
{
	// Test if the driver correctly increase snaplen for statsd traffic
	string payload = "soluta.necessitatibus.voluptatem.consequuntur.dignissimos.repudiandae.nostrum.lorem.ipsum:18|c";

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return m_tid_filter(evt) && ( evt->get_type() == PPME_SOCKET_SENDMSG_X || evt->get_type() == PPME_SOCKET_SENDTO_X);
	};

	//
	// INITIALIZATION
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		// sendto with addr
		// Different port
		udp_client client(0x0100007F, false, 8126);
		client.m_payload = payload;
		client.m_ignore_errors = true;
		client.m_recv = false;
		client.m_n_transactions = 1;
		client.run();

		// sendto without addr (connect)
		client.m_use_connect = true;
		client.run();

		// sendmsg with addr
		client.m_use_connect = false;
		client.m_use_sendmsg = true;
		client.run();

		// sendmsg without addr
		client.m_use_connect = true;
		client.run();
	};

	//
	// OUTPUT VALDATION
	//
	int n = 0;
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		++n;
		EXPECT_EQ(payload.substr(0, 80), e->get_param_value_str("data")) << "Failure on " << e->get_name() << " n=" << n;
	};

	ASSERT_NO_FATAL_FAILURE( {event_capture::run(test, callback, filter);});
	EXPECT_EQ(4, n);
}
