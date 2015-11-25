//
// mesosget.cpp
//
// extracts needed data from the mesos REST API interface,
// translates it to protobuf and prints the result in human readable format
//
// usage: mesosget [http://localhost:80] [v1]
//

#include "sinsp.h"
#include "mesos_common.h"
#include "mesos_http.h"
#include "mesos.h"

sinsp_logger g_logger;

int main(int argc, char** argv)
{
	mesos m("http://54.152.106.80:5050");

	return 0;
}

