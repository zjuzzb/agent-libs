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

#include "sinsp_int.h"
#include "connectinfo.h"

using Poco::NumberFormatter;
using Poco::NumberParser;

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
		if (server == NULL) {
		    fprintf(stderr,(char*)"ERROR, no such host as %s\n", hostname);
		    exit(0);
		}

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
				while(read(sockfd, reqbody, BUFSIZE) != 0)
				{
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
				for(cit = param.m_inspector->m_ipv4_connections->m_connections.begin(); 
					cit != param.m_inspector->m_ipv4_connections->m_connections.end(); ++cit)
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
	configuration.set_analyzer_sample_length_ns(1000000 * ONE_SECOND_IN_NS);

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter, configuration);});

	ASSERT_EQ(N_CONNECTIONS, nconns);
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
				for(cit = param.m_inspector->m_ipv4_connections->m_connections.begin(); 
					cit != param.m_inspector->m_ipv4_connections->m_connections.end(); ++cit)
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
	configuration.set_analyzer_sample_length_ns(1000000 * ONE_SECOND_IN_NS);

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter, configuration);});

	ASSERT_EQ(1, nconns);
}
