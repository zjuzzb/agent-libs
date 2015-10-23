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
#include "k8s_collector.h"
#include "k8s_proto.h"
#include "Poco/Stopwatch.h"
#include "Poco/Exception.h"
#include "Poco/Format.h"
#include "k8s_http.h"
#include <iostream>
#include <thread>
#include <unistd.h>

using Poco::Stopwatch;
using Poco::format;
using Poco::Exception;

sinsp_logger g_logger;

int main(int argc, char** argv)
{
	try
	{
		std::string host("http://localhost:8080");
		if(argc >= 2) host = argv[1];

#ifndef K8S_DISABLE_THREAD
		bool run_watch_thread = true;
		if(argc >= 3)
		{
			if (std::string(argv[2]) == "false")
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

		//Stopwatch sw;
		//sw.start();
		k8s* kube = new k8s(host, true, run_watch_thread);
		//draiosproto::metrics met;
		//k8s_proto kube_proto(met);
		//const draiosproto::k8s_state& proto = kube_proto.get_proto(kube->get_state());
		//sw.stop();
		int i = 0;
		if(run_watch_thread)
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
					if(!kube->is_alive())
					{
						delete kube;
						try
						{
							kube = new k8s(host, true, run_watch_thread);
							kube->watch();
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
						kube = new k8s(host, true, run_watch_thread);
						kube->watch();
					}
					catch(std::exception& ex)
					{
						g_logger.log(ex.what(), sinsp_logger::SEV_ERROR);
						kube = 0;
					}
				}
				
			}
		}
		else
		{
			while (++i < 10)
			{
				if(!run_watch_thread)
				{
					kube->watch();
				}
				//sleep(1);
			}
			//g_logger.log(proto.DebugString());
			sleep(10);
			kube->stop_watching();
			while (true)
			{
				if(!run_watch_thread)
				{
					kube->watch();
				}
				//sleep(1);
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
		return 1;
	}

	return 0;
}

