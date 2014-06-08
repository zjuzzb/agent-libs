#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_int.h"
#include "parser_http.h"

#ifdef HAS_ANALYZER

sinsp_http_parser::sinsp_http_parser()
{
	m_http_options_intval = (*(uint32_t*)HTTP_OPTIONS_STR);
	m_http_get_intval = (*(uint32_t*)HTTP_GET_STR);
	m_http_head_intval = (*(uint32_t*)HTTP_HEAD_STR);
	m_http_post_intval = (*(uint32_t*)HTTP_POST_STR);
	m_http_put_intval = (*(uint32_t*)HTTP_PUT_STR);
	m_http_delete_intval = (*(uint32_t*)HTTP_DELETE_STR);
	m_http_trace_intval = (*(uint32_t*)HTTP_TRACE_STR);
	m_http_connect_intval = (*(uint32_t*)HTTP_CONNECT_STR);
}

bool sinsp_http_parser::is_msg_http(char* buf, uint32_t buflen)
{
	//
	// Make sure there are at least 4 bytes
	//
	if(buflen > 4)
	{
		if(*(uint32_t*)buf == m_http_get_intval ||
		        *(uint32_t*)buf == m_http_post_intval ||
		        *(uint32_t*)buf == m_http_put_intval ||
		        *(uint32_t*)buf == m_http_delete_intval ||
		        *(uint32_t*)buf == m_http_trace_intval ||
		        *(uint32_t*)buf == m_http_connect_intval ||
		        *(uint32_t*)buf == m_http_options_intval)
		{
			return true;
		}
	}

	return false;
}

bool sinsp_http_parser::parse_request(char* buf, uint32_t buflen)
{
	uint32_t j, k;
	char* url = NULL;
	uint32_t url_len;
	bool res = false;

	for(j = 0; j < buflen; j++)
	{
		if(buf[j] == 0)
		{
			return false;
		}

		if(buf[j] == ' ')
		{
			if(url == NULL)
			{
				url = buf + j + 1;
			}
			else if(res == false)
			{
				url_len = (uint32_t)(buf + j - url);
				m_url.assign(url, url_len);
				res = true;
			}
		}

		if(buflen - j > sizeof("User-Agent:") - 1)
		{
			if(buf[j] == 'U' &&
			        buf[j + 1] == 's' &&
			        buf[j + 2] == 'e' &&
			        buf[j + 3] == 'r' &&
			        buf[j + 4] == '-' &&
			        buf[j + 5] == 'A' &&
			        buf[j + 6] == 'g' &&
			        buf[j + 7] == 'e' &&
			        buf[j + 8] == 'n' &&
			        buf[j + 9] == 't' &&
			        buf[j + 10] == ':')
			{
				uint32_t uastart = j + sizeof("User-Agent:");

				for(k = j + sizeof("User-Agent:"); k < buflen; k++)
				{
					if(buf[k] == '\r' || buf[k] == '\n')
					{
						m_agent.assign(buf + uastart, k - uastart);
						break;
					}
				}
			}
		}
	}

	return res;
}

#endif // HAS_ANALYZER
