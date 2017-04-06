//
// kubeget.cpp
//
// extracts needed data from the kubernetes REST API interface,
// translates it to protobuf and prints the result in human readable format
//
// usage: kubeget [http://localhost:80] [v1]
//

#include "sinsp.h"
#include "k8s_common.h"
#include "k8s.h"
#include "k8s_proto.h"
#include "k8s_api_handler.h"
#include "Poco/Stopwatch.h"
#include "Poco/Exception.h"
#include "Poco/Format.h"
#include "Poco/FileStream.h"
#include "Poco/StreamCopier.h"
#include "Poco/DateTime.h"
#include "Poco/DateTimeFormatter.h"
#include "Poco/DateTimeFormat.h"
#include "curl/curl.h"
#include <iostream>
#include <exception>
#include <thread>
#include <unistd.h>
#include <signal.h>
#include <memory>

using namespace Poco;

sinsp_logger g_logger;

void wait_for_termination_request()
{
	sigset_t sset;
	sigemptyset(&sset);
	sigaddset(&sset, SIGINT);
	sigaddset(&sset, SIGQUIT);
	sigaddset(&sset, SIGTERM);
	sigprocmask(SIG_BLOCK, &sset, NULL);
	int sig;
	sigwait(&sset, &sig);
}

class k8s_test
{
public:
	k8s_test(): m_k8s("")
	{
	}

	void get_data(const std::string& component)
	{
		std::ostringstream json;
		get_json(component, json);
		//std::cout << json.str() << std::endl;
		//m_k8s.parse_json(json.str(), k8s_component::type_map::value_type(k8s_component::get_type(component), component));
	}

	k8s& get_k8s()
	{
		return m_k8s;
	}

private:
	static void get_json(const std::string& component, std::ostringstream& json)
	{
		std::string fname = "./test/";
		try
		{
			FileInputStream fis(fname.append(component).append((".json")));
			StreamCopier::copyStream(fis, json);
		}
		catch(FileNotFoundException& ex)
		{
			std::cout << "File not found: " << fname << std::endl;
		}
	}

	k8s m_k8s;
};


void print_cache(k8s& kube)
{
#ifdef K8S_DISABLE_THREAD
	const k8s_state_t& state = kube.get_state();

	const k8s_state_t::namespace_map& ns_map = state.get_namespace_map();
	std::cout << "---------" << " found " << ns_map.size() << " namespaces --------" << std::endl;
	int counter = 0;
	for(const auto& entry : ns_map)
	{
		std::cout << ++counter << "=>" << entry.first << ':' << entry.second->get_uid() << std::endl;
	}
	std::cout << "-----------------------------------" << std::endl << std::endl;

	const k8s_state_t::container_pod_map& cp_map = state.get_container_pod_map();
	std::cout << "---------" << " found " << cp_map.size() << " pods by container --------" << std::endl;
	counter = 0;
	for(const auto& entry : cp_map)
	{
		std::cout << ++counter << "=>" << entry.first << ':' << entry.second->get_name() << std::endl;
	}
	std::cout << "-----------------------------------" << std::endl << std::endl;

	const k8s_state_t::pod_rc_map& pr_map = state.get_pod_rc_map();
	std::cout << "---------" << " found " << pr_map.size() << " controllers by pod --------" << std::endl;
	counter = 0;
	for(const auto& entry : pr_map)
	{
		std::cout << ++counter << "=>" << entry.first << ':' << entry.second->get_name() << std::endl;
	}
	std::cout << "-----------------------------------" << std::endl << std::endl;

	const k8s_state_t::pod_service_map& ps_map = state.get_pod_service_map();
	std::cout << "---------" << " found " << ps_map.size() << " services by pod --------" << std::endl;
	counter = 0;
	for(const auto& entry : ps_map)
	{
		std::cout << ++counter << "=>" << entry.first << ':' << entry.second->get_name() << std::endl;
	}
	std::cout << "-----------------------------------" << std::endl << std::endl;
#endif
}

void print_proto(k8s& kube)
{
	draiosproto::metrics met;
	k8s_proto(met).get_proto(kube.get_state());
	std::cout << met.DebugString() << std::endl;
}

k8s* get_k8s(const std::string& host, bool run_watch_thread = false)
{
	k8s* kube = 0;
	while(!kube)
	{
		try
		{
			kube = new k8s(host, false);
			/*new k8s(k8s_api.to_string(), false,
					   m_k8s_ssl, m_k8s_bt,
					   m_configuration->get_k8s_event_filter(), m_ext_list_ptr);*/
			if(!kube)
			{
				g_logger.log("Error getting kube...", sinsp_logger::SEV_ERROR);
				sleep(1);
			}
		}
		catch (std::exception& ex)
		{
			g_logger.log(ex.what(), sinsp_logger::SEV_ERROR);
			sleep(1);
		}
	}
	return kube;
}

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h> 

int wait(curl_socket_t sockfd, int for_recv, long timeout_ms)
{
	struct timeval tv;
	fd_set infd, outfd, errfd;
	int res;

	tv.tv_sec = timeout_ms / 1000;
	tv.tv_usec = (timeout_ms % 1000) * 1000;

	FD_ZERO(&infd);
	FD_ZERO(&outfd);
	FD_ZERO(&errfd);

	FD_SET(sockfd, &errfd);

	if(for_recv)
	{
		FD_SET(sockfd, &infd);
	}
	else
	{
		FD_SET(sockfd, &outfd);
	}

	res = select(sockfd + 1, &infd, &outfd, &errfd, &tv);
	return res;
}

void check_error(CURLcode res)
{
	if(CURLE_OK != res && CURLE_AGAIN != res)
	{
		std::ostringstream os;
		os << "Error: " << curl_easy_strerror(res);
		throw std::runtime_error(os.str());
	}
}

void run_watch()
{
	size_t iolen;
	std::string url = "http://127.0.0.1:8080/api/v1/watch/namespaces";
	int portno = 8080;
	struct sockaddr_in serv_addr;
	struct hostent *server;

	long sockextr = socket(AF_INET, SOCK_STREAM, 0);
	if (sockextr < 0)
	{
		std::cerr << "ERROR opening socket" << std::endl;
		return;
	}
	server = gethostbyname("127.0.0.1");
	if (server == NULL)
	{
		std::cerr << "ERROR, no such host" << std::endl;
		exit(0);
	}
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
	serv_addr.sin_port = htons(portno);
	if (connect(sockextr,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0)
	{
		std::cerr << "ERROR connecting" << std::endl;
		return;
	}

	if(!wait(sockextr, 0, 5000))
	{
		g_logger.log("Timed out waiting to connect", sinsp_logger::SEV_ERROR);
		return;
	}

	std::ostringstream request;
	request << "GET /api/v1/watch/nodes HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\nConnection: Keep-Alive";
	request << "\r\n";
	iolen = write(sockextr, request.str().c_str(), request.str().size());
	ASSERT (request.str().size() == iolen);
	if(!wait(sockextr, 1, 5000L))
	{
		g_logger.log("Timed out waiting for response", sinsp_logger::SEV_ERROR);
		return;
	}

	g_logger.log(std::string("Collecting data from ") + url, sinsp_logger::SEV_DEBUG);
	
	fd_set infd;
	fd_set errfd;
	FD_ZERO(&errfd);
	FD_ZERO(&infd);
	FD_SET(sockextr, &errfd);
	FD_SET(sockextr, &infd);

	while (true)
	{
		std::cout << '.' << std::flush;
		struct timeval tv;
		tv.tv_sec  = 0;
		tv.tv_usec = 0;
		int res = select(sockextr + 1, &infd, NULL, &errfd, &tv);
		if(res < 0) // error
		{
			std::string err = strerror(errno);
			g_logger.log(err, sinsp_logger::SEV_CRITICAL);
			return;
		}
		else // data or idle
		{
			if(FD_ISSET(sockextr, &infd))
			{
				char buf[1024] = { 0 };
				iolen = 0;
				iolen = read(sockextr, buf, 1024);
				if(iolen > 0)
				{
					std::cout << buf << std::endl;
				}
				else
				{
					std::string err = strerror(errno);
					std::cout << err << std::endl;
					return;
				}
			}
			else
			{
				FD_SET(sockextr, &infd);
			}

			if(FD_ISSET(sockextr, &errfd))
			{
				std::string err = strerror(errno);
				std::cout << err << std::endl;
				return;
			}
			else
			{
				FD_SET(sockextr, &errfd);
			}
			
			sleep(1);
		}
	}
}

unique_ptr<k8s_handler::collector_t> m_k8s_collector;
//unique_ptr<k8s_api_handler>          m_k8s_api_handler;
//bool                                 m_k8s_api_detected = false;
unique_ptr<k8s_api_handler>          m_k8s_ext_handler;
//k8s_ext_list_ptr_t                   m_ext_list_ptr;
bool                                 m_k8s_ext_detect_done = false;

void discover_extensions(const std::string& k8s_api)
{
	if(!m_k8s_ext_detect_done)
	{
		g_logger.log("K8s API extensions handler: detecting extensions.", sinsp_logger::SEV_TRACE);
		if(!m_k8s_ext_handler)
		{
			if(!m_k8s_collector)
			{
				m_k8s_collector.reset(new k8s_handler::collector_t());
			}
			//if(uri(k8s_api).is_secure()) { init_k8s_ssl(k8s_api); }
			m_k8s_ext_handler.reset(new k8s_api_handler(*m_k8s_collector,
														k8s_api, "/apis/extensions/v1beta1", "[.resources[].name]", "1.0"/*,
														m_k8s_ssl, m_k8s_bt*/));
			g_logger.log("K8s API extensions handler: collector created.", sinsp_logger::SEV_TRACE);
		}
		else
		{
			g_logger.log("K8s API extensions handler: collecting data.", sinsp_logger::SEV_TRACE);
			m_k8s_ext_handler->collect_data();
			if(m_k8s_ext_handler->ready())
			{
				g_logger.log("K8s API extensions handler: data received.", sinsp_logger::SEV_TRACE);
				if(m_k8s_ext_handler->error())
				{
					g_logger.log("K8s API extensions handler: data error occurred while detecting API versions.",
								 sinsp_logger::SEV_WARNING);
				}
				else
				{
					const k8s_api_handler::api_list_t& exts = m_k8s_ext_handler->extensions();
					std::ostringstream ostr;
					for(const auto& ext : exts)
					{
						ostr << std::endl << ext;
					}
					g_logger.log("K8s API extensions handler extensions found: " + ostr.str(),
								 sinsp_logger::SEV_DEBUG);
				}
				m_k8s_ext_detect_done = true;
				m_k8s_collector.reset();
				m_k8s_ext_handler.reset();
			}
			else
			{
				g_logger.log("K8s API extensions handler: not ready.", sinsp_logger::SEV_TRACE);
			}
		}
	}
}

int main(int argc, char** argv)
{
	while(!m_k8s_ext_detect_done)
	{
		discover_extensions("http://localhost:8080");
	}
#if 0
	try
	{
		run_watch();
	}
	catch(std::exception& ex)
	{
		std::cout << ex.what() << std::endl;
	}
	DateTime dt;
	std::cout << DateTimeFormatter::format(dt, DateTimeFormat::RFC822_FORMAT) << std::endl;
	return 0;

	k8s_test k8stest;
	Stopwatch sw;
	sw.start();
	k8stest.get_data("namespaces");
	sw.stop();
	std::cout << "************" << (double)sw.elapsed()/1000000 << "************" << std::endl;
	sw.restart();
	k8stest.get_data("nodes");
	sw.stop();
	std::cout << "************" << (double)sw.elapsed()/1000000 << "************" << std::endl;
	sw.restart();
	k8stest.get_data("pods");
	sw.stop();
	std::cout << "************" << (double)sw.elapsed()/1000000 << "************" << std::endl;
	sw.restart();
	k8stest.get_data("replicationcontrollers");
	sw.stop();
	std::cout << "************" << (double)sw.elapsed()/1000000 << "************" << std::endl;
	sw.restart();
	k8stest.get_data("services");
	sw.stop();
	std::cout << "************" << (double)sw.elapsed()/1000000 << "************" << std::endl;
	//print_proto(k8stest.get_k8s());
	//print_cache(k8stest.get_k8s());
	return 0;

	//draiosproto::metrics met;
	//k8s_proto(met).get_proto(state);
	//FileOutputStream fos("proto.out");
	//fos << met.DebugString() << std::endl;
//#endif

	try
	{
		std::string host("http://localhost:8080");
		if(argc >= 2) host = argv[1];

#ifndef K8S_DISABLE_THREAD
		bool run_watch_thread = true;
		if(argc >= 3)
		{
			if(std::string(argv[2]) == "false")
			{
				run_watch_thread = false;
			}
		}
#else
		bool run_watch_thread = false;
		if(argc >= 3 && std::string(argv[2]) == "true")
		{
			g_logger.log(Poco::format("Argument ignored: run_watch_thread=%s", std::string(argv[2])));
		}
#endif

		k8s* kube = get_k8s(host, run_watch_thread);
		//print_proto(*kube);
		//print_cache(*kube);

		int i = 0;
		if(!run_watch_thread)
		{
			while (kube)
			{
				if(kube->is_alive())
				{
					kube->watch();
					std::cout << '.' << std::flush;
					//print_proto(*kube);
					//print_cache(*kube);
					sleep(1);
				}
				else
				{
					delete kube;
					kube = get_k8s(host, run_watch_thread);
				}
			}
		}
		else
		{
			kube->watch();
			while (++i < 10) sleep(1);
			kube->stop_watching();
			std::cout << "stopped -------------------------------" << std::endl;
			sleep(3);
			std::cout << "starting -------------------------------" << std::endl;
			kube->watch();
			std::cout << "started -------------------------------" << std::endl;
			while (true)
			{
				sleep(1);
				if(kube)
				{
					if(kube->is_alive())
					{
						//print_proto(*kube);
					}
					else
					{
						delete kube;
						try
						{
							kube = new k8s(host, true);
						}
						catch(std::exception& ex)
						{
							g_logger.log(ex.what(), sinsp_logger::SEV_ERROR);
							kube = 0;
						}
					}
				}
				else
				{
					try
					{
						kube = new k8s(host, true);
						//kube->watch();
					}
					catch(std::exception& ex)
					{
						g_logger.log(ex.what(), sinsp_logger::SEV_ERROR);
						kube = 0;
					}
				}
				
			}
		}
		
		//g_logger.log("Stopped.");
		/*
		sleep(5);
		kube.watch();
		g_logger.log("Started.");
		g_logger.log(Poco::format("JSON fetched, parsed and protobuf populated in %d%s", (int)(sw.elapsed() / 1000), std::string(" [ms]")));
		g_logger.log(Poco::format("Nodes:\t\t%d", (int)kube.count(k8s_component::K8S_NODES)));
		g_logger.log(Poco::format("Namespaces:\t%d", (int)kube.count(k8s_component::K8S_NAMESPACES)));
		g_logger.log(Poco::format("Pods:\t\t%d", (int)kube.count(k8s_component::K8S_PODS)));
		g_logger.log(Poco::format("Controllers:\t%d", (int)kube.count(k8s_component::K8S_REPLICATIONCONTROLLERS)));
		g_logger.log(Poco::format("Services:\t%d", (int)kube.count(k8s_component::K8S_SERVICES)));
		*/
		sleep(100);
	}
	catch (std::exception& exc)
	{
		g_logger.log(exc.what());
		google::protobuf::ShutdownProtobufLibrary();
		return 1;
	}

	google::protobuf::ShutdownProtobufLibrary();
	//wait_for_termination_request();
#endif
	return 0;
}

