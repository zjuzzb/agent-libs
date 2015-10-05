//
// kubeget.cpp
//
// extracts needed data from the kubernetes REST API interface,
// translates it to protobuf and prints the result in human readable format
//
// usage: kubeget [http://localhost:80] [v1]
//

#include "k8s.h"
#include "Poco/Stopwatch.h"
#include "Poco/Exception.h"
#include <iostream>


using Poco::Stopwatch;
using Poco::Exception;


int main(int argc, char** argv)
{
	try
	{
		std::string uri("http://localhost:80");
		std::string api = "/api/v1/";

		if (argc == 2) uri = argv[1];
		if (argc == 3) api = std::string("/api/") + argv[2];

		std::cout << "Connecting to " << uri << std::endl;
		Stopwatch sw;
		sw.start();
		k8s kube(uri, api);
		kube.get_proto(/*false*/);
		//std::cout << kube.get_proto(false).DebugString() << std::endl;
		sw.stop();
		std::cout << "JSON fetched, parsed and protobuf populated in " << sw.elapsed() / 1000 << " [ms]" << std::endl;
		std::cout << "Nodes:\t\t" << kube.count(k8s_component::K8S_NODES) << std::endl;
		std::cout << "Namespaces:\t" << kube.count(k8s_component::K8S_NAMESPACES) << std::endl;
		std::cout << "Pods:\t\t" << kube.count(k8s_component::K8S_PODS) << std::endl;
		std::cout << "Controllers:\t" << kube.count(k8s_component::K8S_REPLICATIONCONTROLLERS) << std::endl;
		std::cout << "Services:\t" << kube.count(k8s_component::K8S_SERVICES) << std::endl;
		sleep(100);
	}
	catch (Exception& exc)
	{
		std::cerr << exc.displayText() << std::endl;
		return 1;
	}

	return 0;
}
