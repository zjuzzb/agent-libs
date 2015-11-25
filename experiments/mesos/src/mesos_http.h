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
	mesos_http(mesos& mesos, const std::string& url);

	~mesos_http();

	bool get_all_data(std::ostream& os);
/*
	int get_watch_socket(long timeout_ms);

	bool is_connected() const;

	bool on_data();

	void on_error(const std::string& err, bool disconnect);
*/
private:
	bool init();
	void cleanup();
	static size_t write_data(void *ptr, size_t size, size_t nmemb, void *cb);

	//int wait(curl_socket_t sockfd, int for_recv, long timeout_ms);
	static void check_error(CURLcode res);

	CURL*       m_curl;
	mesos&      m_mesos;
	uri         m_url;
	//curl_socket_t m_watch_socket;
	//bool          m_data_ready;
};
/*
inline bool mesos_http::is_connected() const
{
	return m_curl != 0;
}
*/
#endif // HAS_CAPTURE
