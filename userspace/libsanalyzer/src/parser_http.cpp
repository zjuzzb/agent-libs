#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_int.h"
#include "parser_http.h"

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

//
// Builds the URL string and prepends the method character to it
inline void sinsp_http_parser::req_build_url(const char** dest, const char* url, uint32_t url_len, char method)
{
	extend_req_buffer_len(url_len + 2);
	m_req_storage[m_req_storage_pos] = method;
	memcpy(m_req_storage + m_req_storage_pos + 1, url, url_len);
	*dest = m_req_storage + m_req_storage_pos;
	*(m_req_storage + m_req_storage_pos + url_len + 1) = '\0';
	m_req_storage_pos += (url_len + 2);
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
	bool absoluteURI = false;

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
				else
				{
					pathlen = (uint32_t)(buf + j - path);
					m_is_req_valid = true;
					absoluteURI = is_absoluteURI(path, pathlen);
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
			                              sizeof("user-agent:") - 1,
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
			                                  sizeof("host:") - 1,
			                                  &strlen)) != NULL))
			{
				// We ignore the host header if the URI is absolute in
				// obedience to RFC 2616 (section 5.2)
				if(!absoluteURI)
				{
					hostvalid = true;
				}
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

		if(host && hostvalid)
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
			req_assign(&m_result.url, path, pathlen);
			ASSERT(m_result.url > m_req_storage);
			m_result.url--;

			// If we have been given an absolute URI, we can parse the
			// host and path components ourselves
			if(absoluteURI)
			{
				if(decompose_URI(m_result.url, pathlen, &host, hostlen, &path, pathlen))
				{
					req_build_url(&m_result.url, host, hostlen + pathlen, m_result.url[0]);
					if(pathlen > 0)
					{
						req_assign(&m_result.path, path, pathlen);
					}
					else
					{
						m_result.path = nullptr;
					}
				}
			}
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

bool sinsp_http_parser::is_absoluteURI(const char* URI, uint32_t len)
{
	// RFC 2396, section 3: An absoluteURI is in the general form of
	// <scheme>:<scheme-specific-part>
	// This gets a little murkier because <scheme-specific-part> can also
	// contain a : character, so the only 100% reliable way to do this is to
	// know every possible scheme identifier. However, a quick and dirty
	// heuristic is to look for the :// sequence.
	// We also only scan the first 16 characters as a heuristic performance
	// improvement.
	if(len > 16)
	{
		len = 16;
	}
	for(uint32_t i = 0; i < len; ++i)
	{
		if(URI[i] == ':')
		{
			if(URI[i + 1] == '/' && URI[i + 2] == '/')
			{
				return true;
			}
		}
	}
	return false;
}

inline bool sinsp_http_parser::decompose_URI(const char* URI,
                                             uint32_t URI_len,
                                             const char** host_out,
                                             uint32_t& host_len,
                                             const char** path_out,
                                             uint32_t& path_len)
{
	enum
	{
		START,
		HOST,
		PATH,
		END
	} state = START;

	host_len = 0;
	path_len = 0;
	*host_out = nullptr;
	*path_out = nullptr;

	for(uint32_t i = 0; i <= URI_len; ++i)
	{
		switch(state)
		{
		case START:
			// Parse until we find :// and then start parsing the host
			if(URI[i] == ':')
			{
				if(i < URI_len + 2 && URI[i + 1] == '/' && URI[i + 2] == '/')
				{
					i += 3;
					state = HOST;
					host_len = 1;
					*host_out = &URI[i];
				}
			}
			break;

		case HOST:
			// Parse until we find / and then start parsing the path
			if(URI[i] == '/')
			{
				state = PATH;
				path_len = 1;
				*path_out = &URI[i];
			}
			else
			{
				++host_len;
			}
			break;

		case PATH:
			// Parse until we find a path delimiter
			if(URI[i] == ' ' || URI[i] == '?' || URI[i] == ';')
			{
				state = END;
				i = URI_len;
			}
			else
			{
				++path_len;
			}
			break;
		case END:
			ASSERT("Invalid parsing state" == 0);
			return false;
			break;
		}
	}

	if(host_len == 0 && path_len == 0)
	{
		// If we haven't found a host, we're not an absoluteURI and parsing failed
		return false;
	}
	if(*host_out == nullptr && *path_out == nullptr)
	{
		// If we couldn't parse out a host and path, parsing failed
		return false;
	}
	if((host_len > 0 && *host_out == nullptr) || (path_len > 0 && *path_out == nullptr))
	{
		ASSERT(false);
		// We should never get here, but if we do we don't want to blow up
		return false;
	}
	return state != START;
}
