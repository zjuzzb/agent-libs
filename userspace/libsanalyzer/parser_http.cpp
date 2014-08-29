#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_int.h"
#include "parser_http.h"

#ifdef HAS_ANALYZER

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
inline bool sinsp_http_parser::check_and_extract(char* buf, uint32_t buflen,
												 char* tosearch, uint32_t tosearchlen)
{
	uint32_t k;

	if(buflen > tosearchlen)
	{
		if(memcmp(buf, tosearch, tosearchlen - 1) == 0)
		{
			uint32_t uastart = tosearchlen;

			for(k = tosearchlen; k < buflen; k++)
			{
				if(buf[k] == '\r' || buf[k] == '\n')
				{
					m_agent.assign(buf + uastart, k - uastart);
					break;
				}
			}

			return true;
		}
	}

	return false;
}

#define PARSE_REQUEST_N_TO_EXTRACT 2

inline bool sinsp_http_parser::parse_request(char* buf, uint32_t buflen)
{
	uint32_t j;
	char* url = NULL;
	uint32_t url_len;
	bool res = false;
	uint32_t n_extracted = 0;

	for(j = 0; j < buflen; j++)
	{
		if(buf[j] == 0)
		{
			return res;
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

		if(check_and_extract(buf + j, 
			buflen - j,
			(char*)"User-Agent:",
			sizeof("User-Agent:")))
		{
			n_extracted++;
			if(n_extracted == PARSE_REQUEST_N_TO_EXTRACT)
			{
				return true;
			}

			continue;
		}
		else if(check_and_extract(buf + j, 
			buflen - j,
			(char*)"Host:",
			sizeof("Host:")))
		{
			n_extracted++;
			if(n_extracted == PARSE_REQUEST_N_TO_EXTRACT)
			{
				return true;
			}

			continue;
		}
	}

	return res;
}

inline bool sinsp_http_parser::parse_response(char* buf, uint32_t buflen)
{
	uint32_t j;
	char* status_code = NULL;
	uint32_t status_code_len;
	bool res = false;
	uint32_t n_spaces = 0;

	for(j = 0; j < buflen; j++)
	{
		if(buf[j] == 0)
		{
			return res;
		}

		if(buf[j] == ' ')
		{
			n_spaces++;

			if(n_spaces == 1)
			{
				status_code = buf + j + 1;
			}
			else if(res == false)
			{
				status_code_len = (uint32_t)(buf + j - status_code);
				
				if(!sinsp_numparser::tryparsed32_fast(status_code, 
					status_code_len, &m_status_code))
				{
					m_status_code = -1;
				}

				res = true;
			}
		}

		if(check_and_extract(buf + j, 
			buflen - j,
			(char*)"Content-Type:",
			sizeof("Content-Type:")))
		{
			return true;
		}
	}

	return res;
}

bool sinsp_http_parser::parse_buffer(char* buf, uint32_t buflen)
{
	//
	// This checks if the buffer starts with "HTTP"
	//
	if(*(uint32_t*)buf == 0x50545448)
	{
//		m_status_code = 0;
		return parse_response(buf, buflen);
	}
	else
	{
		return parse_request(buf, buflen);
	}
}

#endif // HAS_ANALYZER
