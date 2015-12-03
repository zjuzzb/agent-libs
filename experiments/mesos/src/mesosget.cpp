//
// mesosget.cpp
//
// extracts needed data from the mesos REST API interface,
// translates it to protobuf and prints the result in human readable format
//
// usage: mesosget [http://localhost:80] [v1]
//

#include "sinsp.h"
#include "mesos_proto.h"
#include "mesos_common.h"
#include "mesos_http.h"
#include "mesos.h"
#include "Poco/FileStream.h"

using namespace Poco;

sinsp_logger g_logger;

void print_proto(mesos& m, const std::string& fname)
{
	draiosproto::metrics met;
	mesos_proto(met).get_proto(m.get_state());
	//FileOutputStream fos("/home/alex/sysdig/agent/experiments/mesos/" + fname + ".protodump");
	//fos << met.DebugString();
	std::cout << met.DebugString() << std::endl;
}

int main(int argc, char** argv)
{
	std::string ip_addr = "54.152.106.80";
	mesos m("http://" + ip_addr + ":5050", "/state.json", 
		"http://" + ip_addr + ":8080", mesos::default_groups_api,
		"http://" + ip_addr + ":8080", mesos::default_apps_api);

	print_proto(m, ip_addr);
/*
	ip_addr = "54.152.151.54";
	mesos s1("http://" + ip_addr + ":5051");
	print_proto(s1, ip_addr);
	ip_addr = "54.86.157.224";
	mesos s2("http://" + ip_addr + ":5051");
	print_proto(s2, ip_addr);
	ip_addr = "54.85.0.8";
	mesos s3("http://" + ip_addr + ":5051");
	print_proto(s3, ip_addr);
*/
	return 0;
}
