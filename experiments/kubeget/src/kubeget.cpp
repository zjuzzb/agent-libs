//
// kubeget.cpp
//
// extracts needed data from the kubernetes REST API interface,
// translates it to protobuf and prints the result in human readable format
//
// usage: kubeget [http://localhost:80] [v1]
//


#include "sinsp.h"
#include "k8s.h"
#include "Poco/Stopwatch.h"
#include "Poco/Exception.h"
#include "Poco/Format.h"
#include <iostream>
#include <thread>

using Poco::Stopwatch;
using Poco::format;
using Poco::Exception;

sinsp_logger g_logger;
 
int main(int argc, char** argv)
{
	try
	{
		std::string uri("http://localhost:80");
		std::string api = "/api/v1/";

		if (argc == 2) uri = argv[1];
		if (argc == 3) api = std::string("/api/") + argv[2];


		g_logger.log(std::string("Connecting to ") + uri);
		Stopwatch sw;
		sw.start();
		k8s kube(uri, false, api);
		kube.get_proto();
		while (true)
		{
			g_logger.log("++++++++++++++++++++++++++++++++++++++++");
			g_logger.log(kube.get_proto().DebugString());
			g_logger.log("----------------------------------------");
			sleep(2);
		}
		sw.stop();
		g_logger.log(Poco::format("JSON fetched, parsed and protobuf populated in %d%s", (int)(sw.elapsed() / 1000), std::string(" [ms]")));
		g_logger.log(Poco::format("Nodes:\t\t%d", (int)kube.count(k8s_component::K8S_NODES)));
		g_logger.log(Poco::format("Namespaces:\t%d", (int)kube.count(k8s_component::K8S_NAMESPACES)));
		g_logger.log(Poco::format("Pods:\t\t%d", (int)kube.count(k8s_component::K8S_PODS)));
		g_logger.log(Poco::format("Controllers:\t%d", (int)kube.count(k8s_component::K8S_REPLICATIONCONTROLLERS)));
		g_logger.log(Poco::format("Services:\t%d", (int)kube.count(k8s_component::K8S_SERVICES)));
		//sleep(10);
	}
	catch (Exception& exc)
	{
		g_logger.log(exc.displayText());
		return 1;
	}

	return 0;
}
