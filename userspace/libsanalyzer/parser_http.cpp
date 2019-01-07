#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_int.h"
#include "parser_http.h"

#ifdef HAS_ANALYZER

#define PARSE_REQUEST_N_TO_EXTRACT 2

sinsp_protocol_parser::sinsp_protocol_parser()
{
	m_is_valid = false;
	m_is_req_valid = false;
}

sinsp_protocol_parser::~sinsp_protocol_parser()
{
}

sinsp_http_parser::sinsp_http_parser()
{
	m_req_storage = (char*)m_req_initial_storage;
	m_req_storage_size = sizeof(m_req_initial_storage);

	m_resp_storage = (char*)m_resp_initial_storage;
	m_resp_storage_size = sizeof(m_resp_initial_storage);
}

sinsp_http_parser::~sinsp_http_parser()
{
	if(m_req_storage != m_req_initial_storage)
	{
		free(m_req_storage);
	}

	if(m_resp_storage != m_resp_initial_storage)
	{
		free(m_resp_storage);
	}
}

sinsp_http_parser::proto sinsp_http_parser::get_type()
{
	return sinsp_protocol_parser::PROTO_HTTP;
}

inline const char* sinsp_http_parser::check_and_extract(const char *buf,
							uint32_t buflen,
							char *tosearch,
							uint32_t tosearchlen,
							OUT uint32_t *reslen)
{
	uint32_t k;

	if(buflen > tosearchlen)
	{
		ASSERT(tosearchlen >= 2);

		//
		// Note: '| 0x20' converts to lowercase
		//
		if((buf[0] | 0x20) == tosearch[0] && (buf[1] | 0x20) == tosearch[1])
		{
			if(sinsp_strcmpi(buf, tosearch, tosearchlen - 1))
			{
				uint32_t uastart = tosearchlen;

				// Skip initial white spaces after "tosearch" token
				for(k=uastart; k < buflen && buf[k] == ' '; ++k)
				{
					++uastart;
				}

				for(k = uastart; k < buflen; k++)
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

inline void sinsp_http_parser::req_assign(const char** dest, const char *src, uint32_t len)
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

inline void sinsp_http_parser::resp_assign(const char** dest, const char *src, uint32_t len)
{
	extend_resp_buffer_len(len + 1);
	memcpy(m_resp_storage + m_resp_storage_pos, src, len);
	*dest = m_resp_storage + m_resp_storage_pos;
	*(m_resp_storage + m_resp_storage_pos + len) = 0;
	m_resp_storage_pos += (len + 1);
}

bool sinsp_http_parser::parse_request(const char* buf, uint32_t buflen)
{
	uint32_t j;
	const char *str = nullptr;
	uint32_t strlen;
	uint32_t n_extracted = 0;
	m_req_storage_pos = 0;
	const char *host = nullptr;
	uint32_t hostlen = 0;
	const char *path = nullptr;
	uint32_t pathlen = 0;
	m_is_valid = false;
	m_is_req_valid = false;
	bool hostvalid = false;
	bool agentvalid = false;

	for(j = 0; j < buflen; j++)
	{
		// end of string
		if(buf[j] == 0)
		{
			break;
		}
		
		if(!m_is_req_valid)
		{
			// Search for the first two of these delimiters.
			// The string between them is the path.
			if(buf[j] == ' ' || buf[j] == '?' || buf[j] == ';')
			{
				if(path == NULL)
				{
					path = buf + j + 1;
				}
				else if(m_is_req_valid == false)
				{
					pathlen = (uint32_t)(buf + j - path);
					m_is_req_valid = true;
				}
			}
		}
		else
		{
			// After we decide that the string is a valid
			// http request, we can pull out useragent and host
			if((!agentvalid) &&
				buf[j - 1] == '\n' &&
				((str = check_and_extract(buf + j,
					buflen - j,
					(char*)"user-agent:",
					sizeof("user-agent:")-1,
					&strlen)) != NULL))
			{
				agentvalid = true;
				req_assign(&m_result.agent, str, strlen);
				n_extracted++;
				if(n_extracted == PARSE_REQUEST_N_TO_EXTRACT)
				{
					break;
				}

				continue;
			}
			else if((!hostvalid) &&
				buf[j - 1] == '\n' &&
				((str = check_and_extract(buf + j, 
					buflen - j,
					(char*)"host:",
					sizeof("host:")-1,
					&strlen)) != NULL))
			{
				hostvalid = true;
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

	if(m_is_req_valid)
	{
		m_req_storage[m_req_storage_pos++] = (char)m_result.method;

		if(host)
		{
			// If we found a host string then use it as the start
			// of the url and append the path to it.
			req_assign(&m_result.url, host, hostlen);
			ASSERT(m_result.url > m_req_storage);

			// I (Bryan) was asked in a code review why we are
			// backing up a character.  I don't have any idea. My
			// best guess is that req_assign is broken and this was
			// a hack to the get the pointer in the right place.
			m_result.url--;
			m_req_storage_pos--;
			req_assign(&m_result.path, path, pathlen);
		}
		else
		{
			// If we didn't find a host string then use the path
			// as the url
			req_assign(&m_result.url, path, pathlen);
			ASSERT(m_result.url > m_req_storage);
			m_result.url--;
		}
	}

	return m_is_req_valid;
}

bool sinsp_http_parser::parse_response(const char* buf, uint32_t buflen)
{
	uint32_t j;
	const char *status_code = nullptr;
	uint32_t status_code_len;
	uint32_t n_spaces = 0;
	const char *str = nullptr;
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
				// The text after the first space is the start
				// of the numerical status code
				status_code = buf + j + 1;
			}
			else if(!m_is_valid)
			{
				// Now we've reached the second space so this
				// is the end of the status code
				status_code_len = (uint32_t)(buf + j - status_code);
				
				if(!sinsp_numparser::tryparsed32_fast(status_code, 
					status_code_len, &m_result.status_code))
				{
					return false;
				}

				m_is_valid = true;
			}
		}

		if(m_is_valid)
		{
			if((str = check_and_extract(buf + j, 
				buflen - j,
				(char*)"content-type:",
				sizeof("content-type:")-1,
				&strlen)) != NULL)
			{
				resp_assign(&m_result.content_type, str, strlen);
				return true;
			}			
		}
	}

	return m_is_valid;
}

sinsp_protocol_parser::msg_type sinsp_http_parser::should_parse(sinsp_fdinfo_t* fdinfo, 
								sinsp_partial_transaction::direction dir,
								bool is_switched,
								const char *buf,
								uint32_t buflen)
{
	// We want to quickly throw away anything that doesn't match our scheme
	// so we cast the buffer to an integer and process it numerically.
	const uint64_t MSG_STR_RESP = 0x002E002F50545448; // "HTTP/X.X"
	const uint64_t MSG_STR_RESP_MASK = 0x00FF00FFFFFFFFFF;
	const uint32_t MSG_STR_OPTIONS =  0x4954504f;
	const uint32_t MSG_STR_GET = 0x20544547;
	const uint32_t MSG_STR_HEAD = 0x44414548;
	const uint32_t MSG_STR_POST = 0x54534f50;
	const uint32_t MSG_STR_PUT = 0x20545550;
	const uint32_t MSG_STR_DELETE = 0x454c4544;
	const uint32_t MSG_STR_TRACE = 0x43415254;
	const uint32_t MSG_STR_CONNECT = 0x4e4e4f43;

	// Going back to at least HTTP 1.0, a Full-Response will always
	// start with a "Status-Line" which begins with "HTTP/".
	// https://www.w3.org/Protocols/HTTP/1.0/spec.html#Response
	if((*reinterpret_cast<const uint64_t *>(buf) & MSG_STR_RESP_MASK) == MSG_STR_RESP)
	{
		return sinsp_protocol_parser::MSG_RESPONSE;
	}

	switch(*reinterpret_cast<const uint32_t *>(buf))
	{
	case MSG_STR_GET:
		m_result.method = http_method::GET;
		return sinsp_protocol_parser::MSG_REQUEST;
	case MSG_STR_POST:
		m_result.method = http_method::POST;
		return sinsp_protocol_parser::MSG_REQUEST;
	case MSG_STR_OPTIONS:
		m_result.method = http_method::OPTIONS;
		return sinsp_protocol_parser::MSG_REQUEST;
	case MSG_STR_HEAD:
		m_result.method = http_method::HEAD;
		return sinsp_protocol_parser::MSG_REQUEST;
	case MSG_STR_PUT:
		m_result.method = http_method::PUT;
		return sinsp_protocol_parser::MSG_REQUEST;
	case MSG_STR_DELETE:
		m_result.method = http_method::DELETE;
		return sinsp_protocol_parser::MSG_REQUEST;
	case MSG_STR_TRACE:
		m_result.method = http_method::TRACE;
		return sinsp_protocol_parser::MSG_REQUEST;
	case MSG_STR_CONNECT:
		m_result.method = http_method::CONNECT;
		return sinsp_protocol_parser::MSG_REQUEST;
	default:
		break;
	}

	return sinsp_protocol_parser::MSG_NONE;

}

#endif // HAS_ANALYZER
