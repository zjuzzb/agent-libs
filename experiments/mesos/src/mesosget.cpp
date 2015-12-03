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

sinsp_logger g_logger;

void print_proto(mesos& m)
{
	draiosproto::metrics met;
	mesos_proto(met).get_proto(m.get_state());
	std::cout << met.DebugString() << std::endl;
}

int main(int argc, char** argv)
{
	std::string server = "54.152.106.80";
	mesos m("http://" + server + ":5050", "/state.json", 
		"http://" + server + ":8080", mesos::default_groups_api,
		"http://" + server + ":8080", mesos::default_apps_api);

	print_proto(m);
	mesos s1("http://54.152.151.54:5051");
	print_proto(s1);
	mesos s2("http://54.86.157.224:5051");
	print_proto(s2);
	mesos s3("http://54.85.0.8:5051");
	print_proto(s3);

	return 0;
}
