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
#include "k8s_poller.h"
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
		std::string host("http://localhost:80");

		if(argc >= 2) host = argv[1];

		Stopwatch sw;
		sw.start();
		k8s kube(host, true);
		draiosproto::metrics met;
		k8s_proto kube_proto(met);
		const draiosproto::k8s_state& proto = kube_proto.get_proto(kube.get_state());
		sw.stop();
		kube.start_watching();
		g_logger.log(proto.DebugString());
		sleep(10);
		//kube.stop_watching();
		//g_logger.log("Stopped.");
		/*
		sleep(5);
		kube.start_watching();
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

