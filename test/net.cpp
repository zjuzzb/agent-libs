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
#include <list>
#include <cassert>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/syscall.h>
#include <netdb.h>
#include <sys/socket.h>
#include <Poco/NumberFormatter.h>
#include <Poco/NumberParser.h>
#include "Poco/URIStreamOpener.h"
#include "Poco/StreamCopier.h"
#include "Poco/Path.h"
#include "Poco/URI.h"
#include "Poco/Exception.h"
#include "Poco/Net/HTTPStreamFactory.h"
#include "Poco/Net/FTPStreamFactory.h"
#include "Poco/NullStream.h"

#include "sinsp_int.h"
#include "connectinfo.h"
#include "analyzer_thread.h"
#include "protostate.h"
#include "procfs_parser.h"
#include <array>

using Poco::NumberFormatter;
using Poco::NumberParser;

using Poco::URIStreamOpener;
using Poco::StreamCopier;
using Poco::Path;
using Poco::URI;
using Poco::Exception;
using Poco::Net::HTTPStreamFactory;
using Poco::Net::FTPStreamFactory;
using Poco::NullOutputStream;

#define SITE "www.google.com"
#define SITE1 "www.yahoo.com"
#define BUFSIZE 1024
#define N_CONNECTIONS 2
#define N_REQS_PER_CONNECTION 10

/*
 * error - wrapper for perror
 */
void error(char *msg) {
    perror(msg);
    exit(0);
}

TEST_F(sys_call_test, net_web_requests)
{
	int nconns = 0;
	int mytid = getpid();

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
		int sockfd, n, j, k;
		struct sockaddr_in serveraddr;
		struct hostent *server;
		char *hostname = (char*)SITE;
		int portno = 80;
		string reqstr;
		char reqbody[BUFSIZE] = "GET / HTTP/1.0\n\n";

		// get the server's DNS entry
		server = gethostbyname(hostname);
		ASSERT_TRUE(server) << "ERROR, no such host as " << hostname;

		for(j = 0; j < N_CONNECTIONS; j++)
		{
			// socket: create the socket
			sockfd = socket(AF_INET, SOCK_STREAM, 0);
			if (sockfd < 0)
			{
				error((char*)"ERROR opening socket");
			}

			// build the server's Internet address
			bzero((char *) &serveraddr, sizeof(serveraddr));
			serveraddr.sin_family = AF_INET;
			bcopy((char *)server->h_addr,
			  (char *)&serveraddr.sin_addr.s_addr, server->h_length);
			serveraddr.sin_port = htons(portno);

			// create a connection with the server
			if(connect(sockfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr)) < 0)
			{
				error((char*)"ERROR connecting");
			}

			for(k = 0; k < N_REQS_PER_CONNECTION; k++)
			{
				reqstr = string("GET ") + "/dfw" + NumberFormatter::format(k) + " HTTP/1.0\n\n";

				// send the request
				n = write(sockfd, reqstr.c_str(), reqstr.length());
				if (n < 0)
				{
					error((char*)"ERROR writing to socket");
				}

				// get the server's reply
				bzero(reqbody, BUFSIZE);
				while(true)
				{
					n = read(sockfd, reqbody, BUFSIZE);
					if(n == 0)
					{
						break;
					}
					if(n < 0)
					{
						error((char*)"ERROR reading from socket");
					}
				}
				//printf("Echo from server: %s", reqbody);
			}

			close(sockfd);
		}

		// We use a random call to tee to signal that we're done
		tee(-1, -1, 0, 0);
	};

	//
	// OUTPUT VALIDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt *evt = param.m_evt;

		if(evt->get_type() == PPME_GENERIC_E)
		{
			if(NumberParser::parse(evt->get_param_value_str("ID", false)) == PPM_SC_TEE)
			{
				unordered_map<ipv4tuple, sinsp_connection, ip4t_hash, ip4t_cmp>::iterator cit;
				for(cit = param.m_inspector->m_analyzer->m_ipv4_connections->m_connections.begin();
					cit != param.m_inspector->m_analyzer->m_ipv4_connections->m_connections.end(); ++cit)
				{
					if(cit->second.m_stid == mytid && cit->first.m_fields.m_dport == 80)
					{
						SCOPED_TRACE(nconns);
						nconns++;
					}
				}
				SCOPED_TRACE("evaluating assertions");
				sinsp_threadinfo* ti = evt->get_thread_info();
				ASSERT_EQ((uint64_t) 0, ti->m_ainfo->m_transaction_metrics.get_counter()->m_count_in);
				ASSERT_EQ((uint64_t) 0, ti->m_ainfo->m_transaction_metrics.get_counter()->m_time_ns_in);
				ASSERT_EQ((uint64_t) 0, ti->m_ainfo->m_transaction_metrics.get_max_counter()->m_count_in);
				ASSERT_EQ((uint64_t) 0, ti->m_ainfo->m_transaction_metrics.get_max_counter()->m_time_ns_in);
				// Note: +1 is because of the DNS lookup
				ASSERT_GE(ti->m_ainfo->m_transaction_metrics.get_counter()->m_count_out, (uint64_t) N_CONNECTIONS);
				ASSERT_LE(ti->m_ainfo->m_transaction_metrics.get_counter()->m_count_out, (uint64_t) N_CONNECTIONS + 1);
				ASSERT_NE((uint64_t) 0, ti->m_ainfo->m_transaction_metrics.get_counter()->m_time_ns_out);
				ASSERT_EQ((uint64_t) 1, ti->m_ainfo->m_transaction_metrics.get_max_counter()->m_count_out);
				ASSERT_NE((uint64_t) 0, ti->m_ainfo->m_transaction_metrics.get_max_counter()->m_time_ns_out);
			}
		}
	};

	//
	// Set a very long sample time, so we're sure no connection is removed
	//
	sinsp_configuration configuration;
	configuration.set_analyzer_sample_len_ns(100 * ONE_SECOND_IN_NS);

	// Set DNS port, /etc/services is read only from dragent context
	// port 80 is not needed, because it's http protocol and is autodiscovered
	ports_set known_ports;
	known_ports.set(53);
	configuration.set_known_ports(known_ports);

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter, configuration);});

	ASSERT_EQ(N_CONNECTIONS, nconns);
}

TEST_F(sys_call_test, net_ssl_requests)
{
	auto ret = system("which curl > /dev/null");
	if(ret != 0)
	{
		fprintf(stderr, "Cannot run, curl is not present\n");
		return;
	}

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		auto tinfo = evt->get_thread_info(false);
		return (tinfo != nullptr && tinfo->m_comm == "curl") || m_tid_filter(evt);
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		auto ret = system("curl https://www.google.com > /dev/null 2>&1");
		EXPECT_EQ(0, ret);

		// We use a random call to tee to signal that we're done
		tee(-1, -1, 0, 0);

		return 0;
	};

	//
	// OUTPUT VALIDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt *evt = param.m_evt;

		if(evt->get_type() == PPME_GENERIC_E &&
		   NumberParser::parse(evt->get_param_value_str("ID", false)) == PPM_SC_TEE)
		{
			// curl uses multiple threads so collect all stats
			auto threadtable = param.m_inspector->m_thread_manager->get_threads();
			sinsp_transaction_counters transaction_metrics;
			transaction_metrics.clear();
			for(auto it = threadtable->begin(); it != threadtable->end(); ++it)
			{
				if(it->second.m_comm == "curl")
				{
					transaction_metrics.add(&it->second.m_ainfo->m_transaction_metrics);
				}
			}

			EXPECT_EQ((uint64_t) 0, transaction_metrics.get_counter()->m_count_in);
			EXPECT_EQ((uint64_t) 0, transaction_metrics.get_counter()->m_time_ns_in);
			EXPECT_EQ((uint64_t) 0, transaction_metrics.get_max_counter()->m_count_in);
			EXPECT_EQ((uint64_t) 0, transaction_metrics.get_max_counter()->m_time_ns_in);

			EXPECT_EQ((uint64_t) 1, transaction_metrics.get_counter()->m_count_out);
			EXPECT_NE((uint64_t) 0, transaction_metrics.get_counter()->m_time_ns_out);
			EXPECT_EQ((uint64_t) 1, transaction_metrics.get_max_counter()->m_count_out);
			EXPECT_NE((uint64_t) 0, transaction_metrics.get_max_counter()->m_time_ns_out);
		}
	};

	//
	// Set a very long sample time, so we're sure no connection is removed
	//
	sinsp_configuration configuration;
	configuration.set_analyzer_sample_len_ns(100 * ONE_SECOND_IN_NS);
	ports_set ports;
	ports.set(443);
	configuration.set_known_ports(ports);

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter, configuration);});
}

//
// This test checks the fact that connect can be called on a UDP socket
// so that read/write/send/recv can then be used on the socket, without the overhead
// of specifying the address with every IO operation.
//
TEST_F(sys_call_test, net_double_udp_connect)
{
	int nconns = 0;
	int mytid = getpid();

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
		int sockfd, n;
		struct sockaddr_in serveraddr;
		struct sockaddr_in serveraddr1;
		struct hostent *server;
		struct hostent *server1;
		char *hostname = (char*)SITE;
		char *hostname1 = (char*)SITE1;
		int portno = 80;
		string reqstr;

		// get the first server's DNS entry
		server = gethostbyname(hostname);
		if (server == NULL) {
		    fprintf(stderr,(char*)"ERROR, no such host as %s\n", hostname);
		    exit(0);
		}

		// get the second server's DNS entry
		server1 = gethostbyname(hostname1);
		if(server1 == NULL) {
		    fprintf(stderr,(char*)"ERROR, no such host as %s\n", hostname1);
		    exit(0);
		}

		// create the socket
		sockfd = socket(2, 2, 0);
		if (sockfd < 0)
		{
			error((char*)"ERROR opening socket");
		}

		// build the server's Internet address
		bzero((char *) &serveraddr, sizeof(serveraddr));
		serveraddr.sin_family = AF_INET;
		bcopy((char *)server->h_addr,
		  (char *)&serveraddr.sin_addr.s_addr, server->h_length);
		serveraddr.sin_port = 0;

		// create a connection with google
		if(connect(sockfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr)) < 0)
		{
			error((char*)"ERROR connecting");
		}

		// create a SECOND connection with google
		if(connect(sockfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr)) < 0)
		{
			error((char*)"ERROR connecting");
		}

		// build the server's Internet address
		bzero((char *) &serveraddr1, sizeof(serveraddr1));
		serveraddr1.sin_family = AF_INET;
		bcopy((char *)server1->h_addr,
		  (char *)&serveraddr1.sin_addr.s_addr, server1->h_length);
		serveraddr1.sin_port = htons(portno);

		// create a connection with yahoo
		if(connect(sockfd, (struct sockaddr*)&serveraddr1, sizeof(serveraddr1)) < 0)
		{
			error((char*)"ERROR connecting");
		}

		//
		// Send a datagram
		//
		reqstr = "GET /dfw HTTP/1.0\n\n";

		// send the request
		n = write(sockfd, reqstr.c_str(), reqstr.length());
		if (n < 0)
		{
			error((char*)"ERROR writing to socket");
		}

		//
		// Close the socket
		//
		close(sockfd);

		// We use a random call to tee to signal that we're done
		tee(-1, -1, 0, 0);

		return 0;
	};

	//
	// OUTPUT VALIDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt *evt = param.m_evt;

		if(evt->get_type() == PPME_GENERIC_E)
		{
			if(NumberParser::parse(evt->get_param_value_str("ID", false)) == PPM_SC_TEE)
			{
				unordered_map<ipv4tuple, sinsp_connection, ip4t_hash, ip4t_cmp>::iterator cit;
				for(cit = param.m_inspector->m_analyzer->m_ipv4_connections->m_connections.begin();
					cit != param.m_inspector->m_analyzer->m_ipv4_connections->m_connections.end(); ++cit)
				{
					if(cit->second.m_stid == mytid && cit->first.m_fields.m_dport == 80)
					{
						nconns++;
					}
				}
			}
		}
	};

	//
	// Set a very long sample time, so we're sure no connection is removed
	//
	sinsp_configuration configuration;
	configuration.set_analyzer_sample_len_ns(100 * ONE_SECOND_IN_NS);

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter, configuration);});

	ASSERT_EQ(1, nconns);
}

TEST_F(sys_call_test, net_connection_table_limit)
{
	int nconns = 0;
//	int mytid = getpid();

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
		try
		{
			HTTPStreamFactory::registerFactory();

			NullOutputStream ostr;

			URI uri("http://www.google.com");

			//
			// 5 separate connections
			//
			std::unique_ptr<std::istream> pStr0(URIStreamOpener::defaultOpener().open(uri));
			StreamCopier::copyStream(*pStr0.get(), ostr);

			std::unique_ptr<std::istream> pStr1(URIStreamOpener::defaultOpener().open(uri));
			StreamCopier::copyStream(*pStr1.get(), ostr);

			std::unique_ptr<std::istream> pStr2(URIStreamOpener::defaultOpener().open(uri));
			StreamCopier::copyStream(*pStr2.get(), ostr);

			std::unique_ptr<std::istream> pStr3(URIStreamOpener::defaultOpener().open(uri));
			StreamCopier::copyStream(*pStr3.get(), ostr);

			std::unique_ptr<std::istream> pStr4(URIStreamOpener::defaultOpener().open(uri));
			StreamCopier::copyStream(*pStr4.get(), ostr);
			// We use a random call to tee to signal that we're done
			tee(-1, -1, 0, 0);
		}
		catch (Exception& exc)
		{
			std::cerr << exc.displayText() << std::endl;
			FAIL();
		}

		return;
	};

	//
	// OUTPUT VALIDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt *evt = param.m_evt;

		if(evt->get_type() == PPME_GENERIC_E)
		{
			if(NumberParser::parse(evt->get_param_value_str("ID", false)) == PPM_SC_TEE)
			{
				unordered_map<ipv4tuple, sinsp_connection, ip4t_hash, ip4t_cmp>::iterator cit;
				for(cit = param.m_inspector->m_analyzer->m_ipv4_connections->m_connections.begin();
					cit != param.m_inspector->m_analyzer->m_ipv4_connections->m_connections.end(); ++cit)
				{
					nconns++;
				}

				ASSERT_EQ(3, nconns);
			}
		}
	};

	//
	// Set a very long sample time, so we're sure no connection is removed
	//
	sinsp_configuration configuration;
	configuration.set_analyzer_sample_len_ns(100 * ONE_SECOND_IN_NS);

	//
	// Set a very low connection table size
	//
	configuration.set_max_connection_table_size(3);

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter, configuration);});
}

class analyzer_callback: public analyzer_callback_interface
{
	void sinsp_analyzer_data_ready(uint64_t ts_ns, uint64_t nevts, uint64_t num_drop_events, draiosproto::metrics* metrics, uint32_t sampling_ratio, double analyzer_cpu_pct, double flush_cpu_pct, uint64_t analyzer_flush_duration_ns)
	{
		printf("ciao\n");
	}

	void subsampling_disabled()
	{
	}
};

TEST_F(sys_call_test, DISABLED_net_connection_aggregation)
{
	int nconns = 0;
	analyzer_callback ac;

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
		try
		{
			HTTPStreamFactory::registerFactory();

			NullOutputStream ostr;

			URI uri1("http://www.google.com");
			std::unique_ptr<std::istream> pStr1(URIStreamOpener::defaultOpener().open(uri1));
			StreamCopier::copyStream(*pStr1.get(), ostr);

			URI uri2("http://www.yahoo.com");
			std::unique_ptr<std::istream> pStr2(URIStreamOpener::defaultOpener().open(uri2));
			StreamCopier::copyStream(*pStr2.get(), ostr);

			URI uri3("http://www.bing.com");
			std::unique_ptr<std::istream> pStr3(URIStreamOpener::defaultOpener().open(uri3));
			StreamCopier::copyStream(*pStr3.get(), ostr);

			// We use a random call to tee to signal that we're done
			tee(-1, -1, 0, 0);
//			sleep(5);
		}
		catch (Exception& exc)
		{
			std::cerr << exc.displayText() << std::endl;
			FAIL();
		}

		return;
	};

	//
	// OUTPUT VALIDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
return;
		sinsp_evt *evt = param.m_evt;

		if(evt->get_type() == PPME_GENERIC_E)
		{
			if(NumberParser::parse(evt->get_param_value_str("ID", false)) == PPM_SC_TEE)
			{
				unordered_map<ipv4tuple, sinsp_connection, ip4t_hash, ip4t_cmp>::iterator cit;
				for(cit = param.m_inspector->m_analyzer->m_ipv4_connections->m_connections.begin();
					cit != param.m_inspector->m_analyzer->m_ipv4_connections->m_connections.end(); ++cit)
				{
					nconns++;
				}

				ASSERT_EQ(3, nconns);
			}
		}
	};

	//
	// Set a very low connection table size
	//
	sinsp_configuration configuration;
	configuration.set_analyzer_sample_len_ns(3 * ONE_SECOND_IN_NS);

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter, configuration, &ac);});
}

TEST(sinsp_protostate, test_zero)
{
	sinsp_protostate protostate;
	auto protos = make_unique<draiosproto::proto_info>();
	protostate.to_protobuf(protos.get(), 1, 20);
	EXPECT_FALSE(protos->has_http());
	EXPECT_FALSE(protos->has_mysql());
	EXPECT_FALSE(protos->has_postgres());
	EXPECT_FALSE(protos->has_mongodb());
}

TEST(sinsp_protostate, test_per_container_distribution)
{
	std::array<sinsp_protostate, 80> protostates;
	for(auto& protostate : protostates)
	{
		for(auto j = 0; j < 100; ++j)
		{
			auto transaction = make_unique<sinsp_partial_transaction>();
			auto http_parser = new sinsp_http_parser();
			auto url = string("http://test") + to_string(j);
			http_parser->m_url = const_cast<char*>(url.c_str());
			http_parser->m_status_code = 200;
			http_parser->m_is_valid = true;
			transaction->m_type = sinsp_partial_transaction::TYPE_HTTP;
			transaction->m_protoparser = http_parser;
			protostate.update(transaction.get(), j, false, 512);
		}
	}
	sinsp_protostate_marker marker;
	for(auto& protostate: protostates)
	{
		marker.add(&protostate);
	}
	marker.mark_top(15);
	auto has_urls = 0;
	for(auto& protostate : protostates)
	{
		auto protos = make_unique<draiosproto::proto_info>();
		protostate.to_protobuf(protos.get(), 1, 15);
		if(protos->has_http())
		{
			auto http = protos->http();

			if(http.client_urls().size() > 0)
			{
				has_urls += 1;
			}
		}
		EXPECT_FALSE(protos->has_mysql());
		EXPECT_FALSE(protos->has_postgres());
		EXPECT_FALSE(protos->has_mongodb());
	}
	EXPECT_EQ(15, has_urls);
}

TEST(sinsp_protostate, test_top_call_should_be_present)
{
	std::array<sinsp_protostate, 80> protostates;
	for(auto& protostate : protostates)
	{
		for(auto j = 0; j < 100; ++j)
		{
			auto transaction = make_unique<sinsp_partial_transaction>();
			auto http_parser = new sinsp_http_parser();
			auto url = string("http://test") + to_string(j);
			http_parser->m_url = const_cast<char*>(url.c_str());
			http_parser->m_status_code = 200;
			http_parser->m_is_valid = true;
			transaction->m_type = sinsp_partial_transaction::TYPE_HTTP;
			transaction->m_protoparser = http_parser;
			protostate.update(transaction.get(), j, false, 512);
		}
	}
	{
		auto& protostate = protostates.at(0);
		auto transaction = make_unique<sinsp_partial_transaction>();
		auto http_parser = new sinsp_http_parser();
		auto url = string("http://test/url/slow");
		http_parser->m_url = const_cast<char*>(url.c_str());
		http_parser->m_status_code = 200;
		http_parser->m_is_valid = true;
		transaction->m_type = sinsp_partial_transaction::TYPE_HTTP;
		transaction->m_protoparser = http_parser;
		protostate.update(transaction.get(), 1000, false, 512);
	}

	{
		auto& protostate = protostates.at(50);
		for(auto j = 0; j < 500; ++j)
		{
			auto transaction = make_unique<sinsp_partial_transaction>();
			auto http_parser = new sinsp_http_parser();
			auto url = string("http://test/url/topcall");
			http_parser->m_url = const_cast<char*>(url.c_str());
			http_parser->m_status_code = 204;
			http_parser->m_is_valid = true;
			transaction->m_type = sinsp_partial_transaction::TYPE_HTTP;
			transaction->m_protoparser = http_parser;
			protostate.update(transaction.get(), 2, false, 512);
		}
	}

	sinsp_protostate_marker marker;
	for(auto& protostate: protostates)
	{
		marker.add(&protostate);
	}
	marker.mark_top(15);
	auto found_slow = false;
	auto found_top_call = false;
	auto top_ncalls = 0;
	for(auto& protostate : protostates)
	{
		auto protos = make_unique<draiosproto::proto_info>();
		protostate.to_protobuf(protos.get(), 1, 15);
		if(protos->has_http())
		{
			auto http = protos->http();

			if(http.client_urls().size() > 0)
			{
				for(auto url : http.client_urls())
				{
					if(url.url().find("slow") != string::npos)
					{
						found_slow = true;
					}
					if(url.url().find("topcall") != string::npos)
					{
						found_top_call = true;
					}
				}
			}
			for(auto status_code : http.client_status_codes())
			{
				if(status_code.status_code() == 204)
				{
					top_ncalls = status_code.ncalls();
				}
			}
		}
		EXPECT_FALSE(protos->has_mysql());
		EXPECT_FALSE(protos->has_postgres());
		EXPECT_FALSE(protos->has_mongodb());
	}
	EXPECT_TRUE(found_slow);
	EXPECT_TRUE(found_top_call);
	EXPECT_EQ(500, top_ncalls);
}

TEST(sinsp_procfs_parser, DISABLED_test_read_network_interfaces_stats)
{
	sinsp_procfs_parser parser(1, 1024, true);

	auto stats = parser.read_network_interfaces_stats();
	EXPECT_EQ(stats.first, 0U);
	EXPECT_EQ(stats.second, 0U);
	system("curl https://google.com > /dev/null 2> /dev/null");
	stats = parser.read_network_interfaces_stats();
	EXPECT_GT(stats.first, 0U);
	EXPECT_GT(stats.second, 0U);
}
