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
	typedef void (mesos::*parse_func_t)(const std::string&);
	
	mesos_http(mesos& m, const uri& url);

	~mesos_http();

	bool get_all_data(/*std::ostream& os*/parse_func_t);

	int get_watch_socket(long timeout_ms);

	bool is_connected() const;

	bool on_data();

	void on_error(const std::string& err, bool disconnect);

private:
	bool init();
	int wait(curl_socket_t sockfd, int for_recv, long timeout_ms);
	void cleanup();
	static size_t write_data(void *ptr, size_t size, size_t nmemb, void *cb);

	//int wait(curl_socket_t sockfd, int for_recv, long timeout_ms);
	static void check_error(CURLcode res);

	CURL*         m_curl;
	mesos&        m_mesos;
	std::string   m_protocol;
	std::string   m_credentials;
	std::string   m_host_and_port;
	uri           m_url;
	bool          m_connected;
	std::string   m_component;
	curl_socket_t m_watch_socket;
	bool          m_data_ready;
};

inline bool mesos_http::is_connected() const
{
	return m_connected;
}

#endif // HAS_CAPTURE
