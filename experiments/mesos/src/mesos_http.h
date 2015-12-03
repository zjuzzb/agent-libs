//
// mesos_http.h
//

#pragma once

#ifdef HAS_CAPTURE

#include "curl/curl.h"
#include "uri.h"
#include <iosfwd>
#include <map>
#include <string>

class mesos;

class mesos_http
{
public:
	mesos_http(const std::string& url);

	~mesos_http();

	bool get_all_data(std::ostream& os);

private:
	bool init();
	void cleanup();
	static size_t write_data(void *ptr, size_t size, size_t nmemb, void *cb);

	//int wait(curl_socket_t sockfd, int for_recv, long timeout_ms);
	static void check_error(CURLcode res);

	CURL*       m_curl;
	uri         m_url;
};

#endif // HAS_CAPTURE
