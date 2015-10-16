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

		if (argc >= 2) host = argv[1];

		Stopwatch sw;
		sw.start();
		k8s kube(host, true);
		kube.get_state(true);
		draiosproto::metrics met;
		k8s_proto kube_proto(met);
		const draiosproto::k8s_state& proto = kube_proto.get_proto(kube.get_state());
		sw.stop();
		kube.start_watching();
		g_logger.log(proto.DebugString());
		sleep(10);
		kube.stop_watching();
		g_logger.log("Stopped.");
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
	catch (Exception& exc)
	{
		g_logger.log(exc.displayText());
		return 1;
	}

	return 0;
}


#if 0

#include <stdio.h>
#include <curl/curl.h>
 
 sinsp_logger g_logger;
 
int main(void)
{
  CURL *curl;
  CURLcode res;
 
  curl_global_init(CURL_GLOBAL_DEFAULT);
 
  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://vagrant:vagrant@10.245.1.2/api/v1/nodes");
 
//#ifdef SKIP_PEER_VERIFICATION
    /*
     * If you want to connect to a site who isn't using a certificate that is
     * signed by one of the certs in the CA bundle you have, you can skip the
     * verification of the server's certificate. This makes the connection
     * A LOT LESS SECURE.
     *
     * If you have a CA cert for the server stored someplace else than in the
     * default bundle, then the CURLOPT_CAPATH option might come handy for
     * you.
     */ 
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
	//curl_easy_setopt(curl, CURLOPT_CAPATH, "/home/alex/sysdig/agent/experiments/kubeget/ca-bundle.crt");
//#endif
 
#ifdef SKIP_HOSTNAME_VERIFICATION
    /*
     * If the site you're connecting to uses a different host name that what
     * they have mentioned in their server certificate's commonName (or
     * subjectAltName) fields, libcurl will refuse to connect. You can skip
     * this check, but this will make the connection less secure.
     */ 
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif
 
    /* Perform the request, res will get the return code */ 
    res = curl_easy_perform(curl);
    /* Check for errors */ 
    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));
 
    /* always cleanup */ 
    curl_easy_cleanup(curl);
  }
 
  curl_global_cleanup();
 
  return 0;
}

#endif
