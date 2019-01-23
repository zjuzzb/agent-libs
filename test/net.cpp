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

// For HTTP server
#include <Poco/Net/ServerSocket.h>
#include <Poco/Net/HTTPServer.h>
#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPRequestHandlerFactory.h>
#include <Poco/Net/HTTPResponse.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>


#include "sinsp_int.h"
#include "connectinfo.h"
#include "analyzer_thread.h"
#include "protostate.h"
#include "procfs_parser.h"
#include <array>
#include <thread>

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

using Poco::Net::HTTPServer;
using Poco::Net::HTTPServerRequest;
using Poco::Net::HTTPServerResponse;
using Poco::Net::HTTPServerParams;
using Poco::Net::HTTPResponse;
using Poco::Net::ServerSocket;


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

//
// HTTP server stuff
//

///
/// Handle incoming HTTP requests
///
/// Implements a very simple request handler
///
class HTTPHandler : public Poco::Net::HTTPRequestHandler
{
public:
  virtual void handleRequest(HTTPServerRequest &request, HTTPServerResponse &response)
	{
		response.setStatus(HTTPResponse::HTTP_OK);
		response.setContentType("text/html");

		ostream& out = response.send();
		out << "<html><body>"
		    << "<h1>Sysdig agent test</h1>"
		    << "<p>Request host = " << request.getHost() << "</p>"
		    << "<p>Request URI = "  << request.getURI()  << "</p>"
		    << "</body></html>"
		    << flush;
  }
};

///
/// Build a request handler when requested by the server
///
class HTTPRHFactory : public Poco::Net::HTTPRequestHandlerFactory
{
public:
	static const uint16_t port = 9090;
	virtual HTTPHandler* createRequestHandler(const HTTPServerRequest &)
	{
		return new HTTPHandler;
	}
};

///
/// Make an HTTP request to the built-in server
///
/// This function knows how to connect to the above server class and provides
/// a convenient interface for making a simple request (assuming we don't care
/// about the response).
///
/// @return  true   The request was made successfully
/// @return  false  The request failed before it could be made
///
bool localhost_http_request()
{
	if (!URIStreamOpener::defaultOpener().supportsScheme("http")) {
		try {
			HTTPStreamFactory::registerFactory();
		} catch (...) {
			// If the factory is already registered, that's fine. Carry on.
		}
	}

	try {
		NullOutputStream ostr;
		stringstream ss;
		ss << "http://127.0.0.1:" << HTTPRHFactory::port;
		URI uri(ss.str());

		std::unique_ptr<std::istream> pStr0(URIStreamOpener::defaultOpener().open(uri));
		StreamCopier::copyStream(*pStr0.get(), ostr);
	} catch (Exception& ex) {
		cerr << "Exception: " << ex.displayText() << endl;
		return false;
	}
	return true;
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
		// wget is more reliable than curl for not changing its ssl behavior
		return (tinfo != nullptr && tinfo->m_comm == "wget") || m_tid_filter(evt);
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		auto ret = system("wget https://www.sysdig.com > /dev/null 2>&1");
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
			threadtable->loop([&] (sinsp_threadinfo& tinfo) {
				if(tinfo.m_comm == "wget")
				{
					cout << "Adding wget with m_count_out of " << tinfo.m_ainfo->m_transaction_metrics.get_counter()->m_count_out << endl;
					transaction_metrics.add(&tinfo.m_ainfo->m_transaction_metrics);
				}
				return true;
			});

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
		const int REQUESTS_TO_SEND = 5;
		int num_requests = 0;
		// Spin up a thread to run the HTTP server
	    std::thread ws_thread([&num_requests]
		{
			HTTPServer srv(new HTTPRHFactory, ServerSocket(HTTPRHFactory::port), new HTTPServerParams);

			srv.start();

			while (num_requests < REQUESTS_TO_SEND) {
				std::this_thread::sleep_for(chrono::milliseconds(250));
			}

			srv.stop();
		});

		try
		{
			HTTPStreamFactory::registerFactory();

			NullOutputStream ostr;

			URI uri("http://127.0.0.1:9090");

			// Sleep to give the server time to start up
			std::this_thread::sleep_for(chrono::milliseconds(500));

			std::unique_ptr<std::istream> pStrs[REQUESTS_TO_SEND];
			for (int i = 0; i < REQUESTS_TO_SEND; ++i) {
				pStrs[i] = std::move(std::unique_ptr<std::istream>(URIStreamOpener::defaultOpener().open(uri)));
				StreamCopier::copyStream(*pStrs[i].get(), ostr);
				++num_requests;
			}
			// We use a random call to tee to signal that we're done
			tee(-1, -1, 0, 0);
		}
		catch (Exception& exc)
		{
			std::cerr << exc.displayText() << std::endl;
			FAIL();
		}

		ws_thread.join();
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
	void sinsp_analyzer_data_ready(uint64_t ts_ns,
				       uint64_t nevts,
				       uint64_t num_drop_events,
				       draiosproto::metrics* metrics,
				       uint32_t sampling_ratio,
				       double analyzer_cpu_pct,
				       double flush_cpu_pct,
				       uint64_t analyzer_flush_duration_ns,
				       uint64_t num_suppressed_threads)
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

// "standard" class can be used to access private members
class test_helper
{
public:
    static vector<unordered_map<string, sinsp_url_details>::iterator>* get_server_urls(sinsp_protostate_marker* spm)
    {
        return &spm->m_http.m_server_urls;
    }

    static vector<unordered_map<string, sinsp_url_details>::iterator>* get_client_urls(sinsp_protostate_marker* spm)
    {
        return &spm->m_http.m_client_urls;
    }

    static sinsp_http_parser::Result* get_result(sinsp_http_parser* parser)
    {
	    return &parser->m_result;
    }
};

// need 3 classes of URLs for this test
// -URLs which are in the top 15 in a stat
// -URLs which are not in the top 15, but are in a group and are top in that group
// -URLs which are not in the top 15, but are in a group and NOT top in that group
//
// we'll use 1 for our test...because easier
TEST(sinsp_protostate, test_url_groups)
{
    sinsp_protostate protostate;
    set<string> groups = {".*group.*"};
    protostate.set_url_groups(groups);

    for (int i = 0; i < 5; ++i)
    {
        auto transaction = make_unique<sinsp_partial_transaction>();
        auto http_parser = new sinsp_http_parser();
        auto url = string("http://test");
	test_helper::get_result(http_parser)->url = const_cast<char*>(url.c_str());
	test_helper::get_result(http_parser)->status_code = 200;
        http_parser->m_is_valid = true;
        transaction->m_type = sinsp_partial_transaction::TYPE_HTTP;
        transaction->m_protoparser = http_parser;
        protostate.update(transaction.get(), 1, false, 512);
    }

    for (int i = 0; i < 3; ++i)
    {
        auto transaction = make_unique<sinsp_partial_transaction>();
        auto http_parser = new sinsp_http_parser();
        auto url = string("http://testgroup1");
	test_helper::get_result(http_parser)->url = const_cast<char*>(url.c_str());
	test_helper::get_result(http_parser)->status_code = 200;
        http_parser->m_is_valid = true;
        transaction->m_type = sinsp_partial_transaction::TYPE_HTTP;
        transaction->m_protoparser = http_parser;
        protostate.update(transaction.get(), 1, false, 512);
    }

    auto transaction = make_unique<sinsp_partial_transaction>();
    auto http_parser = new sinsp_http_parser();
    auto url = string("http://testgroup2");
    test_helper::get_result(http_parser)->url = const_cast<char*>(url.c_str());
    test_helper::get_result(http_parser)->status_code = 200;
    http_parser->m_is_valid = true;
    transaction->m_type = sinsp_partial_transaction::TYPE_HTTP;
    transaction->m_protoparser = http_parser;
    protostate.update(transaction.get(), 1, false, 512);

    sinsp_protostate_marker marker;
    marker.add(&protostate);
    marker.mark_top(1);

    auto client_urls = test_helper::get_client_urls(&marker);
    EXPECT_EQ(client_urls->size(), 3);

    for (auto url = client_urls->begin(); url != client_urls->end(); ++url)
    {
        if ((*url)->first == "http://testgroup1")
        {
            EXPECT_GT((*url)->second.m_flags & SRF_INCLUDE_IN_SAMPLE, 0);
        }
        else
        {
            EXPECT_EQ((*url)->second.m_flags & SRF_INCLUDE_IN_SAMPLE, 0);
        }
    }

    delete sinsp_protostate::s_url_groups;
    sinsp_protostate::s_url_groups = NULL;
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
			http_parser->m_result.url = url.c_str();
			http_parser->m_result.status_code = 200;
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
			http_parser->m_result.url = url.c_str();
			http_parser->m_result.status_code = 200;
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
		http_parser->m_result.url = url.c_str();
		http_parser->m_result.status_code = 200;
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
			http_parser->m_result.url = url.c_str();
			http_parser->m_result.status_code = 204;
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
	ASSERT_TRUE(system("curl https://google.com > /dev/null 2> /dev/null") == 0);
	stats = parser.read_network_interfaces_stats();
	EXPECT_GT(stats.first, 0U);
	EXPECT_GT(stats.second, 0U);
}
