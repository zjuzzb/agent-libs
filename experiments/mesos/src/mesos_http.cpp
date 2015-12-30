//
// mesos_http.cpp
//

#ifdef HAS_CAPTURE

#include "mesos_http.h"
#include "curl/curl.h"
#include "curl/easy.h"
#include "curl/curlbuild.h"
#define BUFFERSIZE 512 // b64 needs this macro
#include "b64/encode.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "mesos.h"
#include <sstream>
#include <stdexcept>
#include <unistd.h>

mesos_http::mesos_http(mesos& m, const uri& url):
	m_curl(curl_easy_init()),
	m_mesos(m),
	m_url(url),
	m_connected(true)
{
	if(!m_curl)
	{
		throw sinsp_exception("CURL initialization failed.");
	}

	curl_version_info_data* data = curl_version_info(CURLVERSION_NOW);
	if((m_url.get_scheme() == "https") && !(data->features | CURL_VERSION_SSL))
	{
		cleanup();
		throw sinsp_exception("HTTPS NOT supported");
	}
}

mesos_http::~mesos_http()
{
	cleanup();
}

void mesos_http::cleanup()
{
	if(m_curl)
	{
		curl_easy_cleanup(m_curl);
		m_curl = 0;
	}
}

size_t mesos_http::write_data(void *ptr, size_t size, size_t nmemb, void *cb)
{
	std::string data(reinterpret_cast<const char*>(ptr), static_cast<size_t>(size * nmemb));
	*reinterpret_cast<std::ostream*>(cb) << data << std::flush;
	return size * nmemb;
}

CURLcode mesos_http::get_data(const std::string& url, std::ostream& os)
{
	g_logger.log(std::string("Retrieving data from ") + url, sinsp_logger::SEV_DEBUG);
	curl_easy_setopt(m_curl, CURLOPT_URL, url.c_str());
	curl_easy_setopt(m_curl, CURLOPT_FOLLOWLOCATION, 1L);

	if(m_url.get_scheme() == "https")
	{
		check_error(curl_easy_setopt(m_curl, CURLOPT_SSL_VERIFYPEER , 0));
	}

	curl_easy_setopt(m_curl, CURLOPT_NOSIGNAL, 1); //Prevent "longjmp causes uninitialized stack frame" bug
	curl_easy_setopt(m_curl, CURLOPT_ACCEPT_ENCODING, "deflate");
	curl_easy_setopt(m_curl, CURLOPT_WRITEFUNCTION, &mesos_http::write_data);
	
	curl_easy_setopt(m_curl, CURLOPT_WRITEDATA, &os);
	return curl_easy_perform(m_curl);
}

bool mesos_http::get_all_data(parse_func_t parse)
{
	std::ostringstream os;
	CURLcode res = get_data(m_url.to_string(), os);

	if(res != CURLE_OK)
	{
		g_logger.log(curl_easy_strerror(res), sinsp_logger::SEV_ERROR);
		m_connected = false;
	}
	else
	{
		(m_mesos.*parse)(os.str());
		m_connected = true;
	}

	return res == CURLE_OK;
}

int mesos_http::get_watch_socket(long /*timeout_ms*/)
{
	throw sinsp_exception("Mesos HTTP does not implement watch.");
}

bool mesos_http::on_data()
{
	throw sinsp_exception("Mesos HTTP does not implement watch handlers.");
}

void mesos_http::on_error(const std::string& /*err*/, bool /*disconnect*/)
{
	throw sinsp_exception("Mesos HTTP does not implement watch handlers.");
}

void mesos_http::check_error(CURLcode res)
{
	if(CURLE_OK != res && CURLE_AGAIN != res)
	{
		std::ostringstream os;
		os << "Error: " << curl_easy_strerror(res);
		throw sinsp_exception(os.str());
	}
}

#endif // HAS_CAPTURE
