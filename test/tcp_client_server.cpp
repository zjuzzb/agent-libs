//
// Created by Luca Marturana on 20/08/15.
//
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
#include "tcp_client_server.h"

static const string default_payload = "0123456789QWERTYUIOPASDFGHJKLZXCVBNM";
static const string http_payload = "GET / 0123456789QWERTYUIOPASDFGHJKLZXCVBNM0123456789QWERTYUIOPASDFGHJKLZXCVBNM0123456789QWERTYUIOPASDFGHJKLZXCVBNM0123456789QWERTYUIOPASDFGHJKLZXCVBNM0123456789QWERTYUIOPASDFGHJKLZXCVBNM0123456789QWERTYUIOPASDFGHJKLZXCVBNO";

void runtest(iotype iot,
			 const string& payload = default_payload,
			 bool use_shutdown = false,
			 bool use_accept4 = false,
			 uint32_t ntransactions = 1,
			 bool exit_no_close = false,
			 bool ia32_mode = false)
{
	proc_started_filter client_started_filter;
	proc_started_filter server_started_filter;
	auto stringify_bool = [](bool v)
	{
		if(v)
			return "true";
		else
			return "false";
	};
	unsigned callnum = 0;
	string helper_exe = "./test_helper";
	if(ia32_mode)
	{
		helper_exe += "_32";
	}
	auto iot_s = to_string(iot);
	auto ntransactions_s = to_string(ntransactions);
	proc server_proc(helper_exe, {"tcp_server",
							iot_s.c_str(),
							"false",
							stringify_bool(use_shutdown),
							stringify_bool(use_accept4),
							ntransactions_s.c_str(),
							stringify_bool(exit_no_close)});
	int64_t server_pid;
	int64_t client_pid;
	struct in_addr server_in_addr;
	server_in_addr.s_addr = get_server_address();
	char *server_address = inet_ntoa(server_in_addr);
	string sport;
	int state = 0;
	int ctid;
	proc test_proc(helper_exe, {"tcp_client", server_address,
							iot_s.c_str(),
							payload,
							stringify_bool(false), ntransactions_s,
							stringify_bool(exit_no_close)});
	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		auto tinfo = evt->get_thread_info(false);
		if(tinfo && tinfo->m_exe == helper_exe)
		{
			if(tinfo->m_pid == server_pid)
			{
				return server_started_filter(evt);
			}
			else if(tinfo->m_pid == client_pid)
			{
				return client_started_filter(evt);
			}
		}
		return false;
	};

	//
	// INITIALIZATION
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		auto server_handle = start_process_sync(&server_proc);
		server_pid = get<0>(server_handle).id();
		delete get<1>(server_handle);
		wait_for_message(*(get<2>(server_handle)), "SERVER UP\n");

		auto client_handle = start_process(&test_proc);
		client_pid = get<0>(client_handle).id();
		get<0>(client_handle).wait();
		get<0>(server_handle).wait();

		// We use a random call to tee to signal that we're done
		tee(-1, -1, 0, 0);
	};

	function<void (const callback_param&) > log_param = [](const callback_param& param)
	{
		//cerr << param.m_evt->get_name() << endl;
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
		if((evt->get_type() == PPME_SOCKET_SEND_E ||
		   evt->get_type() == PPME_SOCKET_RECV_E ||
		   evt->get_type() == PPME_SOCKET_SENDTO_E ||
		   evt->get_type() == PPME_SOCKET_RECVFROM_E ||
		   evt->get_type() == PPME_SYSCALL_READ_E ||
		   evt->get_type() == PPME_SYSCALL_WRITE_E ||
		   evt->get_type() == PPME_SYSCALL_READV_E ||
		   evt->get_type() == PPME_SYSCALL_WRITEV_E) &&
		   evt->m_fdinfo->m_type == SCAP_FD_IPV4_SOCK)
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
		else if((evt->get_type() == PPME_SOCKET_RECV_X ||
				evt->get_type() == PPME_SOCKET_RECVFROM_X ||
				evt->get_type() == PPME_SYSCALL_READ_X ||
				evt->get_type() == PPME_SYSCALL_READV_X ||
				evt->get_type() == PPME_SYSCALL_WRITEV_X ||
				evt->get_type() == PPME_SYSCALL_WRITE_X ||
				evt->get_type() == PPME_SOCKET_SENDTO_X ||
				evt->get_type() == PPME_SOCKET_SEND_X) &&
				evt->m_fdinfo->m_type == SCAP_FD_IPV4_SOCK)
		{
			if(evt->get_type() == PPME_SOCKET_RECVFROM_X)
			{
				EXPECT_EQ("NULL", evt->get_param_value_str("tuple"));
			}

			EXPECT_EQ(payload, evt->get_param_value_str("data"));

			log_param(param);
			callnum++;
		}

		if((PPME_SYSCALL_CLOSE_X == evt->get_type() || PPME_SOCKET_SHUTDOWN_X == evt->get_type()) && 0 == state && evt->get_tid() == server_pid)
		{
			if(exit_no_close)
			{
				FAIL();
			}

			state = 1;

			sinsp_threadinfo* ti = evt->get_thread_info();
			ASSERT_EQ(ntransactions, ti->m_ainfo->m_transaction_metrics.get_counter()->m_count_in);
			ASSERT_NE((uint64_t) 0, ti->m_ainfo->m_transaction_metrics.get_counter()->m_time_ns_in);
			ASSERT_EQ((uint64_t) 1, ti->m_ainfo->m_transaction_metrics.get_max_counter()->m_count_in);
			ASSERT_NE((uint64_t) 0, ti->m_ainfo->m_transaction_metrics.get_max_counter()->m_time_ns_in);
		}

		if(!(use_shutdown || exit_no_close))
		{
			if(evt->get_type() == PPME_GENERIC_E)
			{
				if(NumberParser::parse(evt->get_param_value_str("ID", false)) == PPM_SC_TEE)
				{
					sinsp_threadinfo* ti = param.m_inspector->get_thread(server_pid, false, true);
					ASSERT_EQ((uint32_t) payload.length() * ntransactions * 2, (ti->m_ainfo->m_metrics.m_io_net.m_bytes_in + ti->m_ainfo->m_metrics.m_io_net.m_bytes_out));
					ASSERT_EQ((uint32_t)(ntransactions * 2 + 2), (ti->m_ainfo->m_metrics.m_io_net.m_count_in + ti->m_ainfo->m_metrics.m_io_net.m_count_out + ti->m_ainfo->m_metrics.m_io_net.m_count_other));

					ti = param.m_inspector->get_thread(ctid, false, true);
					ASSERT_EQ((uint32_t) payload.length() * ntransactions * 2, (ti->m_ainfo->m_metrics.m_io_net.m_bytes_in + ti->m_ainfo->m_metrics.m_io_net.m_bytes_out));
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

// #ifdef __i386__
// 	EXPECT_EQ(8, callnum);
// #else
	EXPECT_EQ(4 + ntransactions * 8, callnum);
// #endif
}

TEST_F(sys_call_test, tcp_client_server)
{
	runtest(SENDRECEIVE);
}

TEST_F(sys_call_test, tcp_client_server_read_write)
{
	runtest(READWRITE);
}

TEST_F(sys_call_test, tcp_client_server_readv_writev)
{
	runtest(READVWRITEV);
}

TEST_F(sys_call_test, tcp_client_server_shutdown)
{
	runtest(SENDRECEIVE, default_payload, true);
}

TEST_F(sys_call_test, tcp_client_server_accept4)
{
	runtest(SENDRECEIVE, default_payload, false, true);
}

TEST_F(sys_call_test, tcp_client_server_multiple)
{
	runtest(SENDRECEIVE, default_payload, false, false, 10);
}

TEST_F(sys_call_test, tcp_client_server_noclose)
{
	runtest(SENDRECEIVE, default_payload, false, false, 1, true);
}

TEST_F(sys_call_test, tcp_client_server_http_snaplen)
{
	runtest(SENDRECEIVE, http_payload);
}

TEST_F(sys_call_test, tcp_client_server_read_write_http_snaplen)
{
	runtest(READWRITE, http_payload);
}

TEST_F(sys_call_test, tcp_client_server_readv_writev_http_snaplen)
{
	runtest(READVWRITEV, http_payload);
}

TEST_F(sys_call_test, tcp_client_server_with_connection_before_capturing_starts)
{
	Poco::Thread server_thread;
	Poco::Thread client_thread;
	tcp_server server(SENDRECEIVE, true);
	uint32_t server_ip_address = get_server_address();
	tcp_client client(server_ip_address, SENDRECEIVE, default_payload, true);

	Poco::RunnableAdapter<tcp_server> server_runnable(server, &tcp_server::run);
	Poco::RunnableAdapter<tcp_client> client_runnable(client, &tcp_client::run);
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
			ASSERT_EQ((uint64_t) 1, ti->m_ainfo->m_transaction_metrics.get_max_counter()->m_count_in);
			ASSERT_NE((uint64_t) 0, ti->m_ainfo->m_transaction_metrics.get_max_counter()->m_time_ns_in);
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

#ifdef __x86_64__
/* void runtest(iotype iot,
			 bool use_shutdown = false,
			 bool use_accept4 = false,
			 uint32_t ntransactions = 1,
			 bool exit_no_close = false,
			 bool ia32_mode = false) */
TEST_F(sys_call_test32, tcp_client_server)
{
	runtest(SENDRECEIVE, default_payload, false, false, 1, false, true);
}

TEST_F(sys_call_test32, tcp_client_server_read_write)
{
	runtest(READWRITE, default_payload, false, false, 1, false, true);
}

TEST_F(sys_call_test32, tcp_client_server_readv_writev)
{
	runtest(READVWRITEV, default_payload, false, false, 1, false, true);
}

TEST_F(sys_call_test32, tcp_client_server_shutdown)
{
	runtest(SENDRECEIVE, default_payload, true, false, 1, false, true);
}

TEST_F(sys_call_test32, tcp_client_server_accept4)
{
	runtest(SENDRECEIVE, default_payload, false, true, 1, false, true);
}

TEST_F(sys_call_test32, tcp_client_server_multiple)
{
	runtest(SENDRECEIVE, default_payload, false, false, 10, false, true);
}

TEST_F(sys_call_test32, tcp_client_server_noclose)
{
	runtest(SENDRECEIVE, default_payload, false, false, 1, true, true);
}
#endif
