#define VISIBILITY_PRIVATE

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
#include <Poco/NumberParser.h>
#include <list>
#include <cassert>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/syscall.h>

using Poco::StringTokenizer;
using Poco::NumberFormatter;
using Poco::NumberParser;

#include "sinsp_int.h"
#include "analyzer_thread.h"

#define SERVER_PORT     3555
#define SERVER_PORT_STR "3555"
#define PAYLOAD         "0123456789QWERTYUIOPASDFGHJKLZXCVBNM"
#define BUFFER_LENGTH   sizeof(PAYLOAD)
#define FALSE           0

typedef enum iotype
{
	READWRITE,
	SENDRECEIVE,
	READVWRITEV,
}iotype;

class tcp_server_ipv4m
{
public:
	tcp_server_ipv4m(iotype iot, 
		bool wait_for_signal_to_continue = false, 
		bool use_shutdown = false, 
		bool use_accept4 = false, 
		uint32_t ntransactions = 1,
		bool exit_no_close = false)
	{
		m_iot = iot;
		m_wait_for_signal_to_continue = wait_for_signal_to_continue;
		m_use_shutdown = use_shutdown;
		m_use_accept4 = use_accept4;
		m_ntransactions = ntransactions;
		m_exit_no_close = exit_no_close;
	}

	void run()
	{
		int servSock;
		int clntSock;
		struct sockaddr_in6 server_address;
		struct sockaddr_in6 client_address;
		unsigned int client_len;
		uint32_t j;

		int port = (m_exit_no_close)? SERVER_PORT + 2 : SERVER_PORT;

		m_tid = syscall(SYS_gettid);

		/* Create socket for incoming connections */
		if((servSock = socket(AF_INET6, SOCK_STREAM, 0)) < 0)
		{
			perror("socket() failed");
			return;
		}

		/* Construct local address structure */
		memset(&server_address, 0, sizeof(server_address));
		server_address.sin6_family = AF_INET6;
		server_address.sin6_port = htons(port);
		server_address.sin6_addr = in6addr_any;

		int yes = 1;
		if(setsockopt(servSock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
		{
			FAIL() << "setsockopt() failed";
		}

		/* Bind to the local address */
		if(::bind(servSock, (struct sockaddr *) &server_address, sizeof(server_address)) < 0)
		{
			perror("bind() failed");
			FAIL();
			return;
		}
		/* Mark the socket so it will listen for incoming connections */
		if(listen(servSock, 1) < 0)
		{

			close(servSock);
			FAIL() << "listen() failed";
			return;
		}
		do
		{
			/* Set the size of the in-out parameter */
			client_len = sizeof(client_address);
			signal_ready();

			/* Wait for a client to connect */
			if(m_use_accept4)
			{
				if((clntSock = accept4(servSock, (struct sockaddr *) &client_address,
				                      &client_len, 0)) < 0)
				{
					close(servSock);
					FAIL() << "accept() failed";
					break;
				}				
			}
			else
			{
				if((clntSock = accept(servSock, (struct sockaddr *) &client_address,
				                      &client_len)) < 0)
				{
					close(servSock);
					FAIL() << "accept() failed";
					break;
				}				
			}

			//char str[INET6_ADDRSTRLEN];
			//if(inet_ntop(AF_INET6, &client_address.sin6_addr, str, sizeof(str))) 
			//{
			//	printf("Client address is %s\n", str);
			//	printf("Client port is %d\n", ntohs(client_address.sin6_port));
			//}

			/* clntSock is connected to a client! */
			wait_for_continue();
			char echoBuffer[BUFFER_LENGTH];        /* Buffer for echo string */
			int recvMsgSize;                    /* Size of received message */
			for(j = 0; j < m_ntransactions; j++)
			{
				if(m_iot == SENDRECEIVE)
				{
					if((recvMsgSize = recv(clntSock, echoBuffer, BUFFER_LENGTH, 0)) < 0)
					{
						FAIL() << "recv() failed";
						break;
					}

					if(send(clntSock, echoBuffer, recvMsgSize, 0) != recvMsgSize)
					{
						FAIL() << "send() failed";
						break;
					}
				}
				else if(m_iot == READWRITE ||
					m_iot == READVWRITEV)
				{
					if((recvMsgSize = read(clntSock, echoBuffer, BUFFER_LENGTH)) < 0)
					{
						FAIL() << "recv() failed";
						break;
					}

					if(write(clntSock, echoBuffer, recvMsgSize) != recvMsgSize)
					{
						FAIL() << "send() failed";
						break;
					}
				}
			}

			if(m_exit_no_close)
			{
				return;
			}

			if(m_use_shutdown)
			{
				ASSERT_EQ(0,shutdown(clntSock, SHUT_WR));
			}
			else
			{
				close(clntSock);    /* Close client socket */
			}
			break;
		}
		while(0);

		if(m_use_shutdown)
		{
			ASSERT_EQ(0,shutdown(servSock, SHUT_RDWR));
		}
		else
		{
			close(servSock);
		}
	}

	void wait_till_ready()
	{
		m_ready.wait();
	}

	void signal_continue()
	{
		m_continue.set();
	}

	int64_t get_tid()
	{
		return m_tid;
	}

private:
	void signal_ready()
	{
		m_ready.set();
	}

	void wait_for_continue()
	{
		if(m_wait_for_signal_to_continue)
		{
			m_continue.wait();
		}
	}

	Poco::Event m_ready;
	Poco::Event m_continue;
	bool m_wait_for_signal_to_continue;
	int64_t m_tid;
	iotype m_iot;
	bool m_use_shutdown;
	bool m_use_accept4;
	uint32_t m_ntransactions;
	bool m_exit_no_close;
};

class tcp_client_ipv4m
{
public:
	tcp_client_ipv4m(uint32_t server_ip_address, 
		iotype iot, 
		bool on_thread = false, 
		uint32_t ntransactions = 1,
		bool exit_no_close = false)
	{
		m_server_ip_address = server_ip_address;
		m_iot = iot;
		m_on_thread = on_thread;
		m_ntransactions = ntransactions;
		m_exit_no_close = exit_no_close;
	}

	void run()
	{
		int sock;
		struct sockaddr_in server_address;
		char buffer[BUFFER_LENGTH];
		int payload_length;
		int bytes_received;
		uint32_t j;
		int port = (m_exit_no_close)? SERVER_PORT + 2: SERVER_PORT;

		m_tid = syscall(SYS_gettid);

		/* Create a reliable, stream socket using TCP */
		if((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		{
			FAIL() << "socket() failed";
			return;
		}

		/* Construct the server address structure */
		memset(&server_address, 0, sizeof(server_address));     /* Zero out structure */
		server_address.sin_family      = AF_INET;             /* Internet address family */
		server_address.sin_addr.s_addr = m_server_ip_address;   /* Server IP address */
		server_address.sin_port        = htons(port); /* Server port */

		/* Establish the connection to the server */
		if(connect(sock, (struct sockaddr *) &server_address, sizeof(server_address)) < 0)
		{
			perror("connect() failed");
			FAIL();
			return;
		}
		signal_ready();
		wait_for_continue();
		payload_length = strlen(PAYLOAD);          /* Determine input length */

		for(j = 0; j < m_ntransactions; j++)
		{
			/* Send the string to the server */
			if(m_iot == SENDRECEIVE)
			{
				if(send(sock, PAYLOAD, payload_length, 0) != payload_length)
				{
					close(sock);
					FAIL() << "send() sent a different number of bytes than expected";
					return;
				}

				if((bytes_received = recv(sock, buffer, BUFFER_LENGTH - 1, 0)) <= 0)
				{
					close(sock);
					FAIL() << "recv() failed or connection closed prematurely";
					return;
				}

				buffer[bytes_received] = '\0';  /* Terminate the string! */
				ASSERT_STREQ(PAYLOAD, buffer);
			}
			else if(m_iot == READWRITE)
			{
				if(write(sock, PAYLOAD, payload_length) != payload_length)
				{
					close(sock);
					FAIL() << "send() sent a different number of bytes than expected";
					return;
				}

				if((bytes_received = read(sock, buffer, BUFFER_LENGTH - 1)) <= 0)
				{
					close(sock);
					FAIL() << "recv() failed or connection closed prematurely";
					return;
				}

				buffer[bytes_received] = '\0';  /* Terminate the string! */
				ASSERT_STREQ(PAYLOAD, buffer);
			}
			else if(m_iot == READVWRITEV)
			{
				string ps(PAYLOAD);
				int wv_count;
				char msg1[BUFFER_LENGTH / 3 + 1];
				char msg2[BUFFER_LENGTH / 3 + 1];
				char msg3[BUFFER_LENGTH / 3 + 1];
				struct iovec wv[3];

				memcpy(msg1, ps.substr(0, BUFFER_LENGTH / 3).c_str(), BUFFER_LENGTH / 3);
				memcpy(msg2, ps.substr(BUFFER_LENGTH / 3, BUFFER_LENGTH * 2 / 3).c_str(), BUFFER_LENGTH / 3);
				memcpy(msg3, ps.substr(BUFFER_LENGTH * 2 / 3, BUFFER_LENGTH).c_str(), BUFFER_LENGTH / 3);

				wv[0].iov_base = msg1;
				wv[1].iov_base = msg2;
				wv[2].iov_base = msg3;
				wv[0].iov_len  = BUFFER_LENGTH / 3;
				wv[1].iov_len  = BUFFER_LENGTH / 3;
				wv[2].iov_len  = BUFFER_LENGTH / 3;
				wv_count = 3;

				if(writev(sock, wv, wv_count) != payload_length)
				{
					close(sock);
					FAIL() << "send() sent a different number of bytes than expected";
					return;
				}

				if((bytes_received = readv(sock, wv, wv_count)) <= 0)
				{
					close(sock);
					FAIL() << "recv() failed or connection closed prematurely";
					return;
				}
			}
		}

		if(m_exit_no_close)
		{
			return;
		}

		close(sock);
	}

	void wait_till_ready()
	{
		m_ready.wait();
	}

	void signal_continue()
	{
		m_continue.set();
	}

	int64_t get_tid()
	{
		return m_tid;
	}

private:
	void signal_ready()
	{
		m_ready.set();
	}

	void wait_for_continue()
	{
		if(m_on_thread)
		{
			m_continue.wait();
		}
	}

	uint32_t m_server_ip_address;
	iotype m_iot;
	Poco::Event m_ready;
	Poco::Event m_continue;
	int64_t m_tid;
	bool m_on_thread;
	uint32_t m_ntransactions;
	bool m_exit_no_close;
};

void runtest_ipv4m(iotype iot, 
	bool use_shutdown = false, 
	bool use_accept4 = false, 
	uint32_t ntransactions = 1,
	bool exit_no_close = false)
{
	int callnum = 0;
	Poco::Thread server_thread;

	tcp_server_ipv4m server(iot, 
		false, 
		use_shutdown, 
		use_accept4, 
		ntransactions,
		exit_no_close);

	uint32_t server_ip_address = get_server_address();

	struct in_addr server_in_addr;
	server_in_addr.s_addr = get_server_address();

	char *server_address = inet_ntoa(server_in_addr);
	string sport;
	int state = 0;
	int ctid;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		int tid = getpid();
		return evt->get_tid() == server.get_tid() || evt->get_tid() == tid;
	};

	//
	// INITIALIZATION
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		Poco::RunnableAdapter<tcp_server_ipv4m> runnable(server, &tcp_server_ipv4m::run);
		server_thread.start(runnable);
		server.wait_till_ready();

		tcp_client_ipv4m client(server_ip_address, 
			iot, 
			false, 
			ntransactions,
			exit_no_close);

		client.run();

		ctid = client.get_tid();
		server_thread.join(100);

		// We use a random call to tee to signal that we're done
		tee(-1, -1, 0, 0);		
	};

	function<void (const callback_param&) > log_param = [](const callback_param& param)
	{
//		cerr << param.m_evt->get_name() << endl;
	};

	//
	// OUTPUT VALIDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* evt = param.m_evt;
		if(evt->get_type() == PPME_SOCKET_CONNECT_X)
		{
			string tuple = evt->get_param_value_str("tuple");

			EXPECT_NE((sinsp_fdinfo_t*)NULL, evt->m_fdinfo);

			if(evt->m_fdinfo->m_type != SCAP_FD_IPV4_SOCK)
			{
				//
				// Skip non-tcp sockets. Python opens unix sockets
				// to god knows what.
				//
				return;
			}

			StringTokenizer tst(tuple, ">");
			EXPECT_EQ(2, (int)tst.count());
			string srcstr = tst[0].substr(0, tst[0].size() - 1);
			string dststr = tst[1];
			StringTokenizer sst(srcstr, ":");
			StringTokenizer dst(dststr, ":");

			//
			// Looks like python 2.x connect to 127.0.0.1:0 before
			// doing the real connection to port SERVER_PORT_STR.
			// If it does it, we skip it.
			//
			if(dst.count() != 2 || dst[1] == "0")
			{
				return;
			}

			EXPECT_EQ(2, (int)sst.count());
			EXPECT_STREQ(server_address, sst[0].c_str());
			if(sport == "")
			{
				EXPECT_NE("0", sst[1]);
				sport = sst[1];
			}
			else
			{
				EXPECT_EQ(sport, sst[1]);
			}

			EXPECT_EQ(2, (int)dst.count());
			EXPECT_EQ(server_address, dst[0]);
			if(!exit_no_close)
			{
				EXPECT_EQ(SERVER_PORT_STR, dst[1]);
			}
			log_param(param);
			callnum++;
		}
		else if(evt->get_type() == PPME_SOCKET_LISTEN_E)
		{
			EXPECT_EQ("1", evt->get_param_value_str("backlog"));
			log_param(param);
			callnum++;
		}
		else if(evt->get_type() == PPME_SOCKET_LISTEN_X)
		{
			EXPECT_EQ("0", evt->get_param_value_str("res"));
			log_param(param);
			callnum++;
		}
		else if(evt->get_type() == PPME_SOCKET_ACCEPT4_5_E)
		{
			EXPECT_EQ("0", evt->get_param_value_str("flags"));
		}
		else if(evt->get_type() == PPME_SOCKET_ACCEPT_5_X ||
			evt->get_type() == PPME_SOCKET_ACCEPT4_5_X)
		{
			StringTokenizer tst(evt->get_param_value_str("tuple"), ">");
			EXPECT_EQ(2, (int)tst.count());

			string srcstr = tst[0].substr(0, tst[0].size() - 1);
			string dststr = tst[1];
			StringTokenizer sst(srcstr, ":");
			StringTokenizer dst(dststr, ":");

			EXPECT_EQ(2, (int)sst.count());
			EXPECT_STREQ(server_address, sst[0].c_str());
			if(sport == "")
			{
				EXPECT_NE("0", sst[1]);
				sport = sst[1];
			}
			else
			{
				EXPECT_EQ(sport, sst[1]);
			}

			EXPECT_EQ(2, (int)dst.count());
			EXPECT_EQ(server_address, dst[0]);
			if(!exit_no_close)
			{
				EXPECT_EQ(SERVER_PORT_STR, dst[1]);
			}

			log_param(param);
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
		if(evt->get_type() == PPME_SOCKET_SEND_E ||
		        evt->get_type() == PPME_SOCKET_RECV_E ||
		        evt->get_type() == PPME_SOCKET_SENDTO_E ||
		        evt->get_type() == PPME_SOCKET_RECVFROM_E || 
		        evt->get_type() == PPME_SYSCALL_READ_E ||
		        evt->get_type() == PPME_SYSCALL_WRITE_E ||
		        evt->get_type() == PPME_SYSCALL_READV_E ||
		        evt->get_type() == PPME_SYSCALL_WRITEV_E)
		{
			if(evt->get_type() == PPME_SOCKET_RECVFROM_E)
			{
				if(evt->get_param_value_str("tuple") != "")
				{
					EXPECT_EQ("NULL", evt->get_param_value_str("tuple"));
				}
			}

			StringTokenizer tst(evt->get_param_value_str("fd"), ">");
			EXPECT_EQ(3, (int)tst.count());

			string srcstr = tst[1].substr(0, tst[1].size() - 1);
			string dststr = tst[2];
			StringTokenizer sst(srcstr, ":");
			StringTokenizer dst(dststr, ":");

			EXPECT_EQ(2, (int)sst.count());
			EXPECT_EQ('4', tst[0][1]);
			EXPECT_STREQ(server_address, &sst[0].c_str()[0]);
			EXPECT_EQ(sport, sst[1]);

			EXPECT_EQ(2, (int)dst.count());
			EXPECT_EQ(server_address, dst[0]);
			if(!exit_no_close)
			{
				EXPECT_EQ(SERVER_PORT_STR, dst[1]);
			}
			
			log_param(param);
			callnum++;
		}
		else if(evt->get_type() == PPME_SOCKET_RECV_X ||
			evt->get_type() == PPME_SOCKET_RECVFROM_X ||
			evt->get_type() == PPME_SYSCALL_READ_X)
		{
			if(evt->get_type() == PPME_SOCKET_RECVFROM_X)
			{
				EXPECT_EQ("NULL", evt->get_param_value_str("tuple"));				
			}

			EXPECT_EQ(PAYLOAD, evt->get_param_value_str("data"));

			log_param(param);
			callnum++;
		}
		else if(evt->get_type() == PPME_SYSCALL_READV_X)
		{
			string ds = evt->get_param_value_str("data");
			//ds = ds.substr(0, BUFFER_LENGTH / 3);

			EXPECT_EQ(ds, evt->get_param_value_str("data"));

			log_param(param);
			callnum++;
		}

		if((PPME_SYSCALL_CLOSE_X == evt->get_type() || PPME_SOCKET_SHUTDOWN_X == evt->get_type()) && 0 == state && evt->get_tid() == server.get_tid())
		{
			if(exit_no_close)
			{
				FAIL();
			}

			state = 1;

			sinsp_threadinfo* ti = evt->get_thread_info();
			ASSERT_EQ(ntransactions, ti->m_ainfo->m_transaction_metrics.get_counter()->m_count_in);
			ASSERT_NE((uint64_t) 0, ti->m_ainfo->m_transaction_metrics.get_counter()->m_time_ns_in);
			ASSERT_EQ((uint64_t) 1, ti->m_ainfo->m_transaction_metrics.get_min_counter()->m_count_in);
			ASSERT_NE((uint64_t) 0, ti->m_ainfo->m_transaction_metrics.get_min_counter()->m_time_ns_in);
			ASSERT_EQ((uint64_t) 1, ti->m_ainfo->m_transaction_metrics.get_max_counter()->m_count_in);
			ASSERT_NE((uint64_t) 0, ti->m_ainfo->m_transaction_metrics.get_max_counter()->m_time_ns_in);
			ASSERT_LE(ti->m_ainfo->m_transaction_metrics.get_min_counter()->m_time_ns_in,
				ti->m_ainfo->m_transaction_metrics.get_max_counter()->m_time_ns_in);
		}

		if(!(use_shutdown || exit_no_close))
		{
			if(evt->get_type() == PPME_GENERIC_E)
			{
				if(NumberParser::parse(evt->get_param_value_str("ID", false)) == PPM_SC_TEE)
				{
					sinsp_threadinfo* ti = param.m_inspector->get_thread(server.get_tid(), false, true);
					ASSERT_EQ((uint32_t)(BUFFER_LENGTH - 1) * ntransactions * 2, (ti->m_ainfo->m_metrics.m_io_net.m_bytes_in + ti->m_ainfo->m_metrics.m_io_net.m_bytes_out));
					ASSERT_EQ((uint32_t)(ntransactions * 2 + 2), (ti->m_ainfo->m_metrics.m_io_net.m_count_in + ti->m_ainfo->m_metrics.m_io_net.m_count_out + ti->m_ainfo->m_metrics.m_io_net.m_count_other));

					ti = param.m_inspector->get_thread(ctid, false, true);
					ASSERT_EQ((uint32_t)(BUFFER_LENGTH - 1) * ntransactions * 2, (ti->m_ainfo->m_metrics.m_io_net.m_bytes_in + ti->m_ainfo->m_metrics.m_io_net.m_bytes_out));
					ASSERT_EQ((uint32_t)(ntransactions * 2 + 1), (ti->m_ainfo->m_metrics.m_io_net.m_count_in + ti->m_ainfo->m_metrics.m_io_net.m_count_out + ti->m_ainfo->m_metrics.m_io_net.m_count_other));
					//printf("****%d\n", (int)ti->m_ainfo->m_metrics.m_io_net.m_count);
					//printf("****%d\n", (int)ti->m_ainfo->m_metrics.m_io_net.m_bytes);
				}
			}
		}		
	};


	//
	// OUTPUT VALDATION
	//
	sinsp_configuration configuration;
	configuration.set_analyzer_sample_len_ns(100 * ONE_SECOND_IN_NS);
	ports_set known_ports;
	known_ports.set(SERVER_PORT);
	configuration.set_known_ports(known_ports);

	ASSERT_NO_FATAL_FAILURE( { event_capture::run(test, callback, filter, configuration);});
	
//	EXPECT_EQ(4 + ntransactions * 6, (uint32_t)callnum);
}

TEST_F(sys_call_test, tcp_client_server_ipv4m)
{
	runtest_ipv4m(SENDRECEIVE);
}

TEST_F(sys_call_test, tcp_client_server_read_write_ipv4m)
{
	runtest_ipv4m(READWRITE);
}

TEST_F(sys_call_test, tcp_client_server_readv_writev_ipv4m)
{
	runtest_ipv4m(READVWRITEV);
}

TEST_F(sys_call_test, tcp_client_server_shutdown_ipv4m)
{
	runtest_ipv4m(SENDRECEIVE,true);
}

TEST_F(sys_call_test, tcp_client_server_accept4_ipv4m)
{
	runtest_ipv4m(SENDRECEIVE, false, true);
}

TEST_F(sys_call_test, tcp_client_server_multiple_ipv4m)
{
	runtest_ipv4m(SENDRECEIVE, false, false, 10);
}

TEST_F(sys_call_test, tcp_client_server_noclose_ipv4m)
{
	runtest_ipv4m(SENDRECEIVE, false, false, 1, true);
}


TEST_F(sys_call_test, tcp_client_server_with_connection_before_capturing_starts_ipv4m)
{
	Poco::Thread server_thread;
	Poco::Thread client_thread;
	tcp_server_ipv4m server(SENDRECEIVE, true);
	uint32_t server_ip_address = get_server_address();
	tcp_client_ipv4m client(server_ip_address,SENDRECEIVE,true);
	
	Poco::RunnableAdapter<tcp_server_ipv4m> server_runnable(server, &tcp_server_ipv4m::run);
	Poco::RunnableAdapter<tcp_client_ipv4m> client_runnable(client, &tcp_client_ipv4m::run);
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
			sinsp_threadinfo* ti = evt->get_thread_info();
			ASSERT_EQ((uint64_t) 1, ti->m_ainfo->m_transaction_metrics.get_counter()->m_count_in);
			ASSERT_NE((uint64_t) 0, ti->m_ainfo->m_transaction_metrics.get_counter()->m_time_ns_in);
			ASSERT_EQ((uint64_t) 1, ti->m_ainfo->m_transaction_metrics.get_min_counter()->m_count_in);
			ASSERT_NE((uint64_t) 0, ti->m_ainfo->m_transaction_metrics.get_min_counter()->m_time_ns_in);
			ASSERT_EQ((uint64_t) 1, ti->m_ainfo->m_transaction_metrics.get_max_counter()->m_count_in);
			ASSERT_NE((uint64_t) 0, ti->m_ainfo->m_transaction_metrics.get_max_counter()->m_time_ns_in);
			ASSERT_EQ(ti->m_ainfo->m_transaction_metrics.get_min_counter()->m_time_ns_in,
				ti->m_ainfo->m_transaction_metrics.get_max_counter()->m_time_ns_in);
		}

	};

	server_thread.start(server_runnable);
	server.wait_till_ready();
	client_thread.start(client_runnable);
	client.wait_till_ready();

	sinsp_configuration configuration;
	ports_set known_ports;
	known_ports.set(SERVER_PORT);
	configuration.set_known_ports(known_ports);

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter, configuration);});
	ASSERT_EQ(1, state);

}


