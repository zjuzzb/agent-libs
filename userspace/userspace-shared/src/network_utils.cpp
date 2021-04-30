#include "network_utils.h"
#include <curl/curl.h>
#include "uri.h"

namespace {

size_t local_curl_write_callback(const char *ptr, size_t size, size_t nmemb, std::string *json) 
{
	const std::size_t total = size * nmemb;
	json->append(ptr, total);
	return total;
}

}

namespace network_utils {

std::string curl_get(const std::string &uri, const std::string &buffer) 
{
	CURL *curl = curl_easy_init();
	CURLcode res;

	if (curl) 
	{
		if ((res = curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2)) != CURLE_OK) 
		{
			goto read_error;
		}
		if ((res = curl_easy_setopt(curl, CURLOPT_TIMEOUT, 1L)) != CURLE_OK) 
		{
			goto read_error;
		}
		if ((res = curl_easy_setopt(curl, CURLOPT_URL, uri.c_str())) != CURLE_OK) 
		{
			goto read_error;
		}
		if ((res = curl_easy_setopt(curl, CURLOPT_HTTPGET, 1)) != CURLE_OK) 
		{
			goto read_error;
		}
		if ((res = curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1)) != CURLE_OK) 
		{
			goto read_error;
		}
		if ((res = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, local_curl_write_callback)) != CURLE_OK) 
		{
			goto read_error;
		}
		if ((res = curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer)) != CURLE_OK) 
		{
			goto read_error;
		}
		if ((res = curl_easy_perform(curl)) != CURLE_OK) 
		{
			goto read_error;
		}

		curl_easy_cleanup(curl);
		return std::string();
read_error:
		curl_easy_cleanup(curl);
		return std::string(curl_easy_strerror(res));
	} 
	else 
	{
		return std::string("Unable to initialize curl");
	}
}

}
