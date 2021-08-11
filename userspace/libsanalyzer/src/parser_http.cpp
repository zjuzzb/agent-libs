#include "analyzer_int.h"
#include "parser_http.h"
#include "sinsp.h"
#include "sinsp_int.h"

#define PARSE_REQUEST_N_TO_EXTRACT 2

namespace
{
uint32_t s_http_options_intval = (*(uint32_t*)HTTP_OPTIONS_STR);
uint32_t s_http_get_intval = (*(uint32_t*)HTTP_GET_STR);
uint32_t s_http_head_intval = (*(uint32_t*)HTTP_HEAD_STR);
uint32_t s_http_post_intval = (*(uint32_t*)HTTP_POST_STR);
uint32_t s_http_put_intval = (*(uint32_t*)HTTP_PUT_STR);
uint32_t s_http_delete_intval = (*(uint32_t*)HTTP_DELETE_STR);
uint32_t s_http_trace_intval = (*(uint32_t*)HTTP_TRACE_STR);
uint32_t s_http_connect_intval = (*(uint32_t*)HTTP_CONNECT_STR);
uint32_t s_http_resp_intval = (*(uint32_t*)HTTP_RESP_STR);

type_config<uint32_t> c_url_table_size(1024,
                                       "Maximum number of URLs tracked for each protocol state",
                                       "http",
                                       "url_table_size");
}  // namespace

protocol_http* protocol_http::s_protocol_http = new protocol_http();

protocol_http& protocol_http::instance()
{
	return *protocol_http::s_protocol_http;
}

protocol_http::protocol_http()
    : protocol_base(),
      feature_base(HTTP_STATS,
                   &draiosproto::feature_status::set_http_stats_enabled,
                   {PROTOCOL_STATS})
{
}

bool protocol_http::is_protocol(sinsp_evt* evt,
                                sinsp_partial_transaction* trinfo,
                                sinsp_partial_transaction::direction trdir,
                                const uint8_t* buf,
                                uint32_t buflen,
                                uint16_t serverport) const
{
	if (!get_enabled())
	{
		return false;
	}

	uint32_t val32 = *(uint32_t*)buf;

	if (val32 == s_http_get_intval || val32 == s_http_post_intval ||
	    val32 == s_http_put_intval || val32 == s_http_delete_intval ||
	    val32 == s_http_trace_intval || val32 == s_http_connect_intval ||
	    val32 == s_http_options_intval ||
	    (val32 == s_http_resp_intval && buf[4] == '/'))
	{
		return true;
	}

	return false;
}

sinsp_protocol_parser::sinsp_protocol_parser()
{
	m_is_valid = false;
	m_is_req_valid = false;
}

sinsp_protocol_parser::~sinsp_protocol_parser() {}

sinsp_http_parser::sinsp_http_parser()
{
	m_req_storage = (char*)m_req_initial_storage;
	m_req_storage_size = sizeof(m_req_initial_storage);

	m_resp_storage = (char*)m_resp_initial_storage;
	m_resp_storage_size = sizeof(m_resp_initial_storage);
}

sinsp_http_parser::~sinsp_http_parser()
{
	if (m_req_storage != m_req_initial_storage)
	{
		free(m_req_storage);
	}

	if (m_resp_storage != m_resp_initial_storage)
	{
		free(m_resp_storage);
	}
}

sinsp_http_parser::proto sinsp_http_parser::get_type()
{
	return sinsp_protocol_parser::PROTO_HTTP;
}

inline const char* sinsp_http_parser::check_and_extract(const char* buf,
                                                        uint32_t buflen,
                                                        char* tosearch,
                                                        uint32_t tosearchlen,
                                                        OUT uint32_t* reslen)
{
	uint32_t k;

	if (buflen > tosearchlen)
	{
		ASSERT(tosearchlen >= 2);

		//
		// Note: '| 0x20' converts to lowercase
		//
		if ((buf[0] | 0x20) == tosearch[0] && (buf[1] | 0x20) == tosearch[1])
		{
			if (sinsp_strcmpi(buf, tosearch, tosearchlen - 1))
			{
				uint32_t uastart = tosearchlen;

				// Skip initial white spaces after "tosearch" token
				for (k = uastart; k < buflen && buf[k] == ' '; ++k)
				{
					++uastart;
				}

				for (k = uastart; k < buflen; k++)
				{
					if (buf[k] == '\r' || buf[k] == '\n')
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
	if (m_req_storage_pos + len >= m_req_storage_size)
	{
		if (m_req_storage == m_req_initial_storage)
		{
			m_req_storage = NULL;
		}

		m_req_storage_size = m_req_storage_pos + len + 16;

		m_req_storage = (char*)realloc(m_req_storage, m_req_storage_size);
		if (m_req_storage == NULL)
		{
			throw sinsp_exception(
			    "memory allocation error in sinsp_http_parser::extend_req_buffer_len");
		}
	}
}

inline void sinsp_http_parser::req_assign(const char** dest, const char* src, uint32_t len)
{
	extend_req_buffer_len(len + 1);
	memcpy(m_req_storage + m_req_storage_pos, src, len);
	*dest = m_req_storage + m_req_storage_pos;
	*(m_req_storage + m_req_storage_pos + len) = 0;
	m_req_storage_pos += (len + 1);
}

//
// Builds the URL string and prepends the method character to it
inline void sinsp_http_parser::req_build_url(const char** dest,
                                             const char* url,
                                             uint32_t url_len,
                                             char method)
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
	if (m_resp_storage_pos + len >= m_resp_storage_size)
	{
		if (m_resp_storage == m_resp_initial_storage)
		{
			m_resp_storage = NULL;
		}

		m_resp_storage_size = m_resp_storage_pos + len + 16;

		m_resp_storage = (char*)realloc(m_resp_storage, m_resp_storage_size);
		if (m_resp_storage == NULL)
		{
			throw sinsp_exception(
			    "memory allocation error in sinsp_http_parser::extend_resp_buffer_len");
		}
	}
}

inline void sinsp_http_parser::resp_assign(const char** dest, const char* src, uint32_t len)
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
	const char* str = nullptr;
	uint32_t strlen;
	uint32_t n_extracted = 0;
	m_req_storage_pos = 0;
	const char* host = nullptr;
	uint32_t hostlen = 0;
	const char* path = nullptr;
	uint32_t pathlen = 0;
	m_is_valid = false;
	m_is_req_valid = false;
	bool hostvalid = false;
	bool agentvalid = false;
	bool absoluteURI = false;

	for (j = 0; j < buflen; j++)
	{
		// end of string
		if (buf[j] == 0)
		{
			break;
		}

		if (!m_is_req_valid)
		{
			// Search for the first two of these delimiters.
			// The string between them is the path.
			if (buf[j] == ' ' || buf[j] == '?' || buf[j] == ';')
			{
				if (path == NULL)
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
			if ((!agentvalid) && buf[j - 1] == '\n' &&
			    ((str = check_and_extract(buf + j,
			                              buflen - j,
			                              (char*)"user-agent:",
			                              sizeof("user-agent:") - 1,
			                              &strlen)) != NULL))
			{
				agentvalid = true;
				req_assign(&m_result.agent, str, strlen);
				n_extracted++;
				if (n_extracted == PARSE_REQUEST_N_TO_EXTRACT)
				{
					break;
				}

				continue;
			}
			else if ((!hostvalid) && buf[j - 1] == '\n' &&
			         ((str = check_and_extract(buf + j,
			                                   buflen - j,
			                                   (char*)"host:",
			                                   sizeof("host:") - 1,
			                                   &strlen)) != NULL))
			{
				// We ignore the host header if the URI is absolute in
				// obedience to RFC 2616 (section 5.2)
				if (!absoluteURI)
				{
					hostvalid = true;
				}
				host = str;
				hostlen = strlen;
				n_extracted++;
				if (n_extracted == PARSE_REQUEST_N_TO_EXTRACT)
				{
					break;
				}

				continue;
			}
		}
	}

	if (m_is_req_valid)
	{
		m_req_storage[m_req_storage_pos++] = (char)m_result.method;

		if (host && hostvalid)
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
			if (absoluteURI)
			{
				if (decompose_URI(m_result.url, pathlen, &host, hostlen, &path, pathlen))
				{
					req_build_url(&m_result.url, host, hostlen + pathlen, m_result.url[0]);
					if (pathlen > 0)
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
	const char* status_code = nullptr;
	uint32_t status_code_len;
	uint32_t n_spaces = 0;
	const char* str = nullptr;
	uint32_t strlen;
	m_resp_storage_pos = 0;

	for (j = 0; j < buflen; j++)
	{
		if (buf[j] == 0)
		{
			return m_is_valid;
		}

		if (buf[j] == ' ')
		{
			n_spaces++;

			if (n_spaces == 1)
			{
				// The text after the first space is the start
				// of the numerical status code
				status_code = buf + j + 1;
			}
			else if (!m_is_valid)
			{
				// Now we've reached the second space so this
				// is the end of the status code
				status_code_len = (uint32_t)(buf + j - status_code);

				if (!sinsp_numparser::tryparsed32_fast(status_code,
				                                       status_code_len,
				                                       &m_result.status_code))
				{
					return false;
				}

				m_is_valid = true;
			}
		}

		if (m_is_valid)
		{
			if ((str = check_and_extract(buf + j,
			                             buflen - j,
			                             (char*)"content-type:",
			                             sizeof("content-type:") - 1,
			                             &strlen)) != NULL)
			{
				resp_assign(&m_result.content_type, str, strlen);
				return true;
			}
		}
	}

	return m_is_valid;
}

sinsp_protocol_parser::msg_type sinsp_http_parser::should_parse(
    sinsp_fdinfo_t* fdinfo,
    sinsp_partial_transaction::direction dir,
    bool is_switched,
    const char* buf,
    uint32_t buflen)
{
	// We want to quickly throw away anything that doesn't match our scheme
	// so we translate (as efficiently as possible) the first few bytes of the
	// buffer to an integer and process it numerically.
	//
	// Going back to at least HTTP 1.0, a Full-Response will always
	// start with a "Status-Line" which begins with "HTTP/".
	// https://www.w3.org/Protocols/HTTP/1.0/spec.html#Response

	const char* HTTP_RESP8_STR = "HTTP/\x00.\x00";   // "HTTP/X.X", vers digits masked
	uint64_t MSG_STR_RESP8 = (*(uint64_t*)HTTP_RESP8_STR);

	const char* HTTP_RESP8_MASK_STR = "\xff\xff\xff\xff\xff\x00\xff\x00";
	uint64_t MSG_STR_RESP8_MASK = (*(uint64_t*)HTTP_RESP8_MASK_STR);

	uint64_t val64 = *(reinterpret_cast<const uint64_t*>(buf));
	if ((val64 & MSG_STR_RESP8_MASK) == MSG_STR_RESP8)
	{
		return sinsp_protocol_parser::MSG_RESPONSE;
	}

	// Look at the first 4 bytes for other recognized packets.
	// start with a "Status-Line" which begins with "HTTP/".
	// https://www.w3.org/Protocols/HTTP/1.0/spec.html#Response
	uint32_t val32 = *(reinterpret_cast<const uint32_t*>(buf));

	if (val32 == s_http_get_intval)
	{
		m_result.method = http_method::GET;
		return sinsp_protocol_parser::MSG_REQUEST;
	}

	if (val32 == s_http_post_intval)
	{
		m_result.method = http_method::POST;
		return sinsp_protocol_parser::MSG_REQUEST;
	}

	if (val32 == s_http_options_intval)
	{
		m_result.method = http_method::OPTIONS;
		return sinsp_protocol_parser::MSG_REQUEST;
	}

	if (val32 == s_http_head_intval)
	{
		m_result.method = http_method::HEAD;
		return sinsp_protocol_parser::MSG_REQUEST;
	}

	if (val32 == s_http_put_intval)
	{
		m_result.method = http_method::PUT;
		return sinsp_protocol_parser::MSG_REQUEST;
	}

	if (val32 == s_http_delete_intval)
	{
		m_result.method = http_method::DELETE;
		return sinsp_protocol_parser::MSG_REQUEST;
	}

	if (val32 == s_http_trace_intval)
	{
		m_result.method = http_method::TRACE;
		return sinsp_protocol_parser::MSG_REQUEST;
	}

	if (val32 == s_http_connect_intval)
	{
		m_result.method = http_method::CONNECT;
		return sinsp_protocol_parser::MSG_REQUEST;
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
	if (len > 16)
	{
		len = 16;
	}
	for (uint32_t i = 0; i < len; ++i)
	{
		if (URI[i] == ':')
		{
			if (URI[i + 1] == '/' && URI[i + 2] == '/')
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

	for (uint32_t i = 0; i <= URI_len; ++i)
	{
		switch (state)
		{
		case START:
			// Parse until we find :// and then start parsing the host
			if (URI[i] == ':')
			{
				if (i < URI_len + 2 && URI[i + 1] == '/' && URI[i + 2] == '/')
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
			if (URI[i] == '/')
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
			if (URI[i] == ' ' || URI[i] == '?' || URI[i] == ';')
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

	if (host_len == 0 && path_len == 0)
	{
		// If we haven't found a host, we're not an absoluteURI and parsing failed
		return false;
	}
	if (*host_out == nullptr && *path_out == nullptr)
	{
		// If we couldn't parse out a host and path, parsing failed
		return false;
	}
	if ((host_len > 0 && *host_out == nullptr) || (path_len > 0 && *path_out == nullptr))
	{
		ASSERT(false);
		// We should never get here, but if we do we don't want to blow up
		return false;
	}
	return state != START;
}

void sinsp_http_state::update(sinsp_partial_transaction* tr,
                              uint64_t time_delta,
                              bool is_server,
                              uint32_t truncation_size)
{
	ASSERT(tr->m_protoparser != NULL);

	if (tr->m_protoparser->m_is_valid)
	{
		sinsp_http_parser* pp = (sinsp_http_parser*)tr->m_protoparser;
		bool is_error = ((pp->result().status_code >= 400) && (pp->result().status_code < 600));

		//
		// Update total counts
		//
		request_sorter<std::string, sinsp_request_details>::update(
		    is_server ? &m_server_totals : &m_client_totals,
		    tr,
		    time_delta,
		    is_error,
		    m_percentiles);

		//
		// Update the URL table
		//
		if (c_url_table_size.get_value() != 0)
		{
			auto& table = is_server ? m_server_urls : m_client_urls;
			auto url = truncate_str(pp->result().url, truncation_size);
			if (table.size() < c_url_table_size.get_value() || table.find(url) != table.end())
			{
				request_sorter<std::string, sinsp_url_details>::update(&table[url],
				                                                       tr,
				                                                       time_delta,
				                                                       is_error,
				                                                       m_percentiles);
			}
		}

		//
		// Update the status code table
		//
		sinsp_request_details* status_code_entry;
		if (is_server)
		{
			status_code_entry = &(m_server_status_codes[pp->result().status_code]);
		}
		else
		{
			status_code_entry = &(m_client_status_codes[pp->result().status_code]);
		}
		status_code_entry->m_ncalls += 1;
	}
}

void sinsp_http_state::add(sinsp_http_state* other)
{
	//
	// Add the URLs
	//
	request_sorter<string, sinsp_url_details>::merge_maps(&m_server_urls, &(other->m_server_urls));
	request_sorter<string, sinsp_url_details>::merge_maps(&m_client_urls, &(other->m_client_urls));
	request_sorter<uint32_t, sinsp_request_details>::merge_maps(&m_server_status_codes,
	                                                            &(other->m_server_status_codes));
	request_sorter<uint32_t, sinsp_request_details>::merge_maps(&m_client_status_codes,
	                                                            &(other->m_client_status_codes));

	m_server_totals += other->m_server_totals;
	m_client_totals += other->m_client_totals;
}

void sinsp_http_state::url_table_to_protobuf(draiosproto::http_info* protobuf_msg,
                                             unordered_map<string, sinsp_url_details>* table,
                                             bool is_server,
                                             uint32_t sampling_ratio,
                                             uint32_t limit)
{
	draiosproto::url_details* ud;

	//
	// The table is small enough that we don't need to sort it
	//
	uint32_t j = 0;
	for (auto uit = table->begin(); j < limit && uit != table->end(); ++uit, ++j)
	{
		if (uit->second.m_flags & (uint32_t)SRF_INCLUDE_IN_SAMPLE)
		{
			if (is_server)
			{
				ud = protobuf_msg->add_server_urls();
			}
			else
			{
				ud = protobuf_msg->add_client_urls();
			}

			ud->set_url(uit->first);
			uit->second.to_protobuf(ud->mutable_counters(),
			                        sampling_ratio,
			                        [&](const sinsp_request_details::percentile_ptr_t pct) {
				                        percentile_to_protobuf(ud->mutable_counters(), pct);
			                        });
		}
	}
}

void sinsp_http_state::status_code_table_to_protobuf(
    draiosproto::http_info* protobuf_msg,
    unordered_map<uint32_t, sinsp_request_details>* table,
    bool is_server,
    uint32_t sampling_ratio,
    uint32_t limit)
{
	draiosproto::status_code_details* ud;
	//
	// The table is small enough that we don't need to sort it
	//
	uint32_t j = 0;
	for (auto uit = table->begin(); j < limit && uit != table->end(); ++uit, ++j)
	{
		if (uit->second.m_flags & (uint32_t)SRF_INCLUDE_IN_SAMPLE)
		{
			if (is_server)
			{
				ud = protobuf_msg->add_server_status_codes();
			}
			else
			{
				ud = protobuf_msg->add_client_status_codes();
			}

			ud->set_status_code(uit->first);
			ud->set_ncalls(uit->second.m_ncalls * sampling_ratio);
		}
	}
}

void sinsp_http_state::to_protobuf(draiosproto::http_info* protobuf_msg,
                                   uint32_t sampling_ratio,
                                   uint32_t limit)
{
	if (m_server_urls.size() != 0)
	{
		url_table_to_protobuf(protobuf_msg, &m_server_urls, true, sampling_ratio, limit);
	}

	if (m_client_urls.size() != 0)
	{
		url_table_to_protobuf(protobuf_msg, &m_client_urls, false, sampling_ratio, limit);
	}

	if (m_server_status_codes.size() != 0)
	{
		status_code_table_to_protobuf(protobuf_msg,
		                              &m_server_status_codes,
		                              true,
		                              sampling_ratio,
		                              limit);
	}

	if (m_client_status_codes.size() != 0)
	{
		status_code_table_to_protobuf(protobuf_msg,
		                              &m_client_status_codes,
		                              false,
		                              sampling_ratio,
		                              limit);
	}

	draiosproto::counter_proto_entry* totals;

	if (m_server_totals.get_time_tot())
	{
		totals = protobuf_msg->mutable_server_totals();
		m_server_totals.to_protobuf(totals,
		                            sampling_ratio,
		                            [&](const sinsp_request_details::percentile_ptr_t pct) {
			                            percentile_to_protobuf(totals, pct);
		                            });
	}

	if (m_client_totals.get_time_tot())
	{
		totals = protobuf_msg->mutable_client_totals();
		m_client_totals.to_protobuf(totals,
		                            sampling_ratio,
		                            [&](const sinsp_request_details::percentile_ptr_t pct) {
			                            percentile_to_protobuf(totals, pct);
		                            });
	}
}

void sinsp_http_state::coalesce_protobuf(draiosproto::http_info* protobuf_msg,
                                         uint32_t sampling_ratio)
{
	// don't bother with URLs and statuses since we're just duplicating host
	// data at that point

	draiosproto::counter_proto_entry* totals;

	if (m_server_totals.get_time_tot())
	{
		totals = protobuf_msg->mutable_server_totals();
		m_server_totals.coalesce_protobuf(totals, sampling_ratio);
	}

	if (m_client_totals.get_time_tot())
	{
		totals = protobuf_msg->mutable_client_totals();
		m_client_totals.coalesce_protobuf(totals, sampling_ratio);
	}
}
