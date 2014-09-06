#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_int.h"
#include "parser_http.h"

#ifdef HAS_ANALYZER

#define PARSE_REQUEST_N_TO_EXTRACT 2

sinsp_protocol_parser::sinsp_protocol_parser()
{
	m_is_valid = false;
}

sinsp_protocol_parser::~sinsp_protocol_parser()
{
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
sinsp_http_parser::sinsp_http_parser()
{
	m_req_storage = (char*)m_req_initial_storage;
	m_req_storage_size = sizeof(m_req_initial_storage);

	m_resp_storage = (char*)m_resp_initial_storage;
	m_resp_storage_size = sizeof(m_resp_initial_storage);
}

inline char* sinsp_http_parser::check_and_extract(char* buf, uint32_t buflen,
												 char* tosearch, uint32_t tosearchlen,
												 OUT uint32_t* reslen)
{
	uint32_t k;

	if(buflen > tosearchlen)
	{
		ASSERT(tosearchlen >= 2);

		if(buf[0] == tosearch[0] && buf[1] == tosearch[1])
		{
			if(memcmp(buf, tosearch, tosearchlen - 1) == 0)
			{
				uint32_t uastart = tosearchlen;

				for(k = tosearchlen; k < buflen; k++)
				{
					if(buf[k] == '\r' || buf[k] == '\n')
					{
						*reslen = k - uastart;
						return buf + uastart;
					}
				}
			}
		}
	}

	return NULL;
}

inline void sinsp_http_parser::extend_req_buffer_len(uint32_t len)
{
	if(m_req_storage_pos + len >= m_req_storage_size)
	{
		if(m_req_storage == m_req_initial_storage)
		{
			m_req_storage = NULL;
		}

		m_req_storage_size = m_req_storage_pos + len + 16;

		m_req_storage = (char*)realloc(m_req_storage, m_req_storage_size);
		if(m_req_storage == NULL)
		{
			throw sinsp_exception("memory allocation error in sinsp_http_parser::extend_req_buffer_len");
		}
	}
}

inline void sinsp_http_parser::req_assign(char** dest, char* src, uint32_t len)
{
	extend_req_buffer_len(len + 1);
	memcpy(m_req_storage + m_req_storage_pos, src, len);
	*dest = m_req_storage + m_req_storage_pos;
	*(m_req_storage + m_req_storage_pos + len) = 0;
	m_req_storage_pos += (len + 1);
}

inline void sinsp_http_parser::extend_resp_buffer_len(uint32_t len)
{
	if(m_resp_storage_pos + len >= m_resp_storage_size)
	{
		if(m_resp_storage == m_resp_initial_storage)
		{
			m_resp_storage = NULL;
		}

		m_resp_storage_size = m_resp_storage_pos + len + 16;

		m_resp_storage = (char*)realloc(m_resp_storage, m_resp_storage_size);
		if(m_resp_storage == NULL)
		{
			throw sinsp_exception("memory allocation error in sinsp_http_parser::extend_resp_buffer_len");
		}
	}
}

inline void sinsp_http_parser::resp_assign(char** dest, char* src, uint32_t len)
{
	extend_resp_buffer_len(len + 1);
	memcpy(m_resp_storage + m_resp_storage_pos, src, len);
	*dest = m_resp_storage + m_resp_storage_pos;
	*(m_resp_storage + m_resp_storage_pos + len) = 0;
	m_resp_storage_pos += (len + 1);
}

bool sinsp_http_parser::parse_request(char* buf, uint32_t buflen)
{
	uint32_t j;
	char* str = NULL;
	uint32_t strlen;
	uint32_t n_extracted = 0;
	m_req_storage_pos = 0;
	char* host = NULL;
	uint32_t hostlen;
	char* path = NULL;
	uint32_t pathlen;
	m_is_valid = false;

	for(j = 0; j < buflen; j++)
	{
		if(buf[j] == 0)
		{
			break;
		}

		if(buf[j] == ' ')
		{
			if(path == NULL)
			{
				path = buf + j + 1;
			}
			else if(m_is_valid == false)
			{
				pathlen = (uint32_t)(buf + j - path);
				m_is_valid = true;
			}
		}

		if(m_is_valid == true)
		{
			if((str = check_and_extract(buf + j,
				buflen - j,
				(char*)"User-Agent:",
				sizeof("User-Agent:"),
				&strlen)) != NULL)
			{
				req_assign(&m_agent, str, strlen);
				n_extracted++;
				if(n_extracted == PARSE_REQUEST_N_TO_EXTRACT)
				{
					break;
				}

				continue;
			}
			else if((str = check_and_extract(buf + j, 
				buflen - j,
				(char*)"Host:",
				sizeof("Host:"),
				&strlen)) != NULL)
			{
				host = str;
				hostlen = strlen;
				n_extracted++;
				if(n_extracted == PARSE_REQUEST_N_TO_EXTRACT)
				{
					break;
				}

				continue;
			}
		}
	}

	if(m_is_valid == true)
	{
		if(host != NULL)
		{
			req_assign(&m_url, host, hostlen);
			m_req_storage_pos--;
			req_assign(&m_path, path, pathlen);
		}
		else
		{
			req_assign(&m_url, path, pathlen);
		}
	}

	return m_is_valid;
}

bool sinsp_http_parser::parse_response(char* buf, uint32_t buflen)
{
	uint32_t j;
	char* status_code = NULL;
	uint32_t status_code_len;
	m_is_valid = false;
	uint32_t n_spaces = 0;
	char* str = NULL;
	uint32_t strlen;
	m_resp_storage_pos = 0;

	for(j = 0; j < buflen; j++)
	{
		if(buf[j] == 0)
		{
			return m_is_valid;
		}

		if(buf[j] == ' ')
		{
			n_spaces++;

			if(n_spaces == 1)
			{
				status_code = buf + j + 1;
			}
			else if(m_is_valid == false)
			{
				status_code_len = (uint32_t)(buf + j - status_code);
				
				if(!sinsp_numparser::tryparsed32_fast(status_code, 
					status_code_len, &m_status_code))
				{
					m_status_code = -1;
				}

				m_is_valid = true;
			}
		}

		if(m_is_valid == true)
		{
			if((str = check_and_extract(buf + j, 
				buflen - j,
				(char*)"Content-Type:",
				sizeof("Content-Type:"),
				&strlen)) != NULL)
			{
				resp_assign(&m_content_type, str, strlen);
				return true;
			}			
		}
	}

	return m_is_valid;
}

bool sinsp_http_parser::is_request(char* buf, uint32_t buflen)
{
	//
	// This checks if the buffer starts with "HTTP"
	//
	if(*(uint32_t*)buf == 0x50545448)
	{
		return false;
	}
	else
	{
		return true;
	}
}

#endif // HAS_ANALYZER
