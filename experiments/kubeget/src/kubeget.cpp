//
// kubeget.cpp
//
// extracts needed data from the kubernetes REST API interface,
// translates it to protobuf and prints the result in human readable format
//
// usage: kubeget [http://localhost:80] [v1]
//

#include "kubernetes.h"
#include "Poco/URI.h"
#include "Poco/Exception.h"


using Poco::URI;
using Poco::Exception;


int main(int argc, char** argv)
{
	try
	{
		URI uri("http://localhost:80");
		std::string api = "/api/v1/";

		if (argc == 2) uri = argv[1];
		if (argc == 3) api = std::string("/api/") + argv[2];

		kubernetes k8s(uri, api);
		std::cout << k8s.get_proto().DebugString() << std::endl;
	}
	catch (Exception& exc)
	{
		std::cerr << exc.displayText() << std::endl;
		return 1;
	}

	return 0;
}
