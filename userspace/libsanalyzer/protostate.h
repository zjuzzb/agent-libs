#ifdef HAS_ANALYZER

#pragma once

///////////////////////////////////////////////////////////////////////////////
// The protocol parser interface class
///////////////////////////////////////////////////////////////////////////////
class sinsp_protocol_parser
{
public:
	enum msg_type
	{
		MSG_NONE = 0,
		MSG_REQUEST,
		MSG_RESPONSE,
	};

	sinsp_protocol_parser();
	virtual ~sinsp_protocol_parser();
	virtual msg_type should_parse(char* buf, uint32_t buflen) = 0;
	virtual bool parse_request(char* buf, uint32_t buflen) = 0;
	virtual bool parse_response(char* buf, uint32_t buflen) = 0;

	bool m_is_valid;
	bool m_is_req_valid;
};

#include "parser_http.h"

///////////////////////////////////////////////////////////////////////////////
// The DPI-based protocol detector
///////////////////////////////////////////////////////////////////////////////
class sinsp_proto_detector
{
public:
	sinsp_proto_detector();

	inline sinsp_partial_transaction::type detect_proto(sinsp_partial_transaction *trinfo,
		char* buf, uint32_t buflen)
	{
		//
		// Make sure there are at least 4 bytes
		//
		if(buflen >= MIN_VALID_PROTO_BUF_SIZE)
		{
			if(*(uint32_t*)buf == m_http_get_intval ||
					*(uint32_t*)buf == m_http_post_intval ||
					*(uint32_t*)buf == m_http_put_intval ||
					*(uint32_t*)buf == m_http_delete_intval ||
					*(uint32_t*)buf == m_http_trace_intval ||
					*(uint32_t*)buf == m_http_connect_intval ||
					*(uint32_t*)buf == m_http_options_intval ||
					(*(uint32_t*)buf == m_http_resp_intval && buf[4] == '/'))
			{
				sinsp_http_parser* st = new sinsp_http_parser;
				ASSERT(trinfo->m_protoparser == NULL);
				trinfo->m_protoparser = (sinsp_protocol_parser*)st;

				return sinsp_partial_transaction::TYPE_HTTP;
			}
			else
			{
				ASSERT(trinfo->m_protoparser == NULL);
				trinfo->m_protoparser = NULL;
				return sinsp_partial_transaction::TYPE_IP;
			}
		}

		ASSERT(trinfo->m_protoparser == NULL);
		trinfo->m_protoparser = NULL;
		return sinsp_partial_transaction::TYPE_IP;		
	}

	bool parse_request(char* buf, uint32_t buflen);

	string m_url;
	string m_agent;

private:
	uint32_t m_http_options_intval;
	uint32_t m_http_get_intval;
	uint32_t m_http_head_intval;
	uint32_t m_http_post_intval;
	uint32_t m_http_put_intval;
	uint32_t m_http_delete_intval;
	uint32_t m_http_trace_intval;
	uint32_t m_http_connect_intval;
	uint32_t m_http_resp_intval;
};

///////////////////////////////////////////////////////////////////////////////
// URL table entry
///////////////////////////////////////////////////////////////////////////////
class sinsp_url_details
{
public:
	enum udflags
	{
		UF_NONE = 0,
		UF_INCLUDE_IN_SAMPLE = 1
	};

	sinsp_url_details()
	{
		m_ncalls = 0;
		m_flags = UF_NONE;
	}

	uint32_t m_ncalls;		// number of times this url has been served
	uint64_t m_time_tot;	// total time spent serving this request
	uint64_t m_time_min;	// fastest time spent serving this request
	uint64_t m_time_max;	// slowest time spent serving this request
	uint32_t m_bytes_in;	// received bytes for this request
	uint32_t m_bytes_out;	// sent bytes for this request
	udflags m_flags;
};

///////////////////////////////////////////////////////////////////////////////
// The protocol state class
///////////////////////////////////////////////////////////////////////////////
typedef bool (*url_comparer)(unordered_map<string, sinsp_url_details>::iterator src, unordered_map<string, sinsp_url_details>::iterator dst);

class sinsp_protostate
{
public:
	inline void update(sinsp_partial_transaction* tr,
		uint64_t time_delta,
		bool is_server)
	{
		if(tr->m_type == sinsp_partial_transaction::TYPE_HTTP)
		{
			ASSERT(tr->m_protoparser != NULL);

			if(tr->m_protoparser->m_is_valid)
			{
				sinsp_http_parser* pp = (sinsp_http_parser*)tr->m_protoparser;

				//
				// Update the URL table
				//
				sinsp_url_details* entry;

				if(is_server)
				{
					entry = &(m_server_urls[pp->m_url]);
				}
				else
				{
					entry = &(m_client_urls[pp->m_url]);
				}

				if(entry->m_ncalls == 0)
				{
					entry->m_ncalls = 1;
					entry->m_time_tot = time_delta;
					entry->m_time_min = time_delta;
					entry->m_time_max = time_delta;
					entry->m_bytes_in = tr->m_bytes_in;
					entry->m_bytes_out = tr->m_bytes_out;
				}
				else
				{
					entry->m_ncalls++;
					entry->m_time_tot += time_delta;
					entry->m_bytes_in += tr->m_bytes_in;
					entry->m_bytes_out += tr->m_bytes_out;

					if(time_delta < entry->m_time_min)
					{
						entry->m_time_min = time_delta;
					}

					if(time_delta > entry->m_time_max)
					{
						entry->m_time_max = time_delta;
					}
				}

				//
				// Update the status code table
				//
				unordered_map<uint32_t, uint32_t>::iterator scit;

				if(is_server)
				{
					scit = m_server_status_codes.find(pp->m_status_code);
					if(scit != m_server_status_codes.end())
					{
						scit->second++;
					}
					else
					{
						m_server_status_codes[pp->m_status_code] = 1;
					}
				}
				else
				{
					scit = m_client_status_codes.find(pp->m_status_code);
					if(scit != m_client_status_codes.end())
					{
						scit->second++;
					}
					else
					{
						m_client_status_codes[pp->m_status_code] = 1;
					}
				}
			}
		}
	}

	inline void clear()
	{
		m_server_urls.clear();
		m_client_urls.clear();
		m_server_status_codes.clear();
		m_client_status_codes.clear();
	}

	void add(sinsp_protostate* other)
	{
		unordered_map<string, sinsp_url_details>::iterator uit;
		unordered_map<string, sinsp_url_details>* pom;
		unordered_map<uint32_t, uint32_t>::iterator scit;
		unordered_map<uint32_t, uint32_t>::iterator scit1;
		unordered_map<uint32_t, uint32_t>* psc;

		//
		// Add the server URLs
		//
		pom = &(other->m_server_urls);

		for(uit = pom->begin(); uit != pom->end(); ++uit)
		{
			sinsp_url_details* entry = &(m_server_urls[uit->first]);

			if(entry->m_ncalls == 0)
			{
				*entry = uit->second;
			}
			else
			{
				entry->m_ncalls += uit->second.m_ncalls;
				entry->m_time_tot += uit->second.m_time_tot;
				entry->m_bytes_in += uit->second.m_bytes_in;
				entry->m_bytes_out += uit->second.m_bytes_out;
				
				if(uit->second.m_time_min < entry->m_time_min)
				{
					entry->m_time_min = uit->second.m_time_min;
				}

				if(uit->second.m_time_max > entry->m_time_max)
				{
					entry->m_time_max = uit->second.m_time_max;
				}
			}
		}

		//
		// Add the client URLs
		//
		pom = &(other->m_client_urls);

		for(uit = pom->begin(); uit != pom->end(); ++uit)
		{
			sinsp_url_details* entry = &(m_client_urls[uit->first]);

			if(entry->m_ncalls == 0)
			{
				*entry = uit->second;
			}
			else
			{
				entry->m_ncalls += uit->second.m_ncalls;
				entry->m_time_tot += uit->second.m_time_tot;
				entry->m_bytes_in += uit->second.m_bytes_in;
				entry->m_bytes_out += uit->second.m_bytes_out;

				if(uit->second.m_time_min < entry->m_time_min)
				{
					entry->m_time_min = uit->second.m_time_min;
				}

				if(uit->second.m_time_max > entry->m_time_max)
				{
					entry->m_time_max = uit->second.m_time_max;
				}
			}
		}

		//
		// Add the status codes
		//
		psc = &(other->m_server_status_codes);

		for(scit = psc->begin(); scit != psc->end(); ++scit)
		{
			scit1 = m_server_status_codes.find(scit->first);

			if(scit1 == m_server_status_codes.end())
			{
				m_server_status_codes[scit->first] = scit->second;
			}
			else
			{
				m_server_status_codes[scit->first] += scit->second;
			}
		}

		psc = &(other->m_client_status_codes);

		for(scit = psc->begin(); scit != psc->end(); ++scit)
		{
			scit1 = m_client_status_codes.find(scit->first);

			if(scit1 == m_client_status_codes.end())
			{
				m_client_status_codes[scit->first] = scit->second;
			}
			else
			{
				m_client_status_codes[scit->first] += scit->second;
			}
		}
	}

	void to_protobuf(draiosproto::proto_info* protobuf_msg, uint32_t sampling_ratio);

	// The list of URLs
	unordered_map<string, sinsp_url_details> m_server_urls;
	unordered_map<string, sinsp_url_details> m_client_urls;
	unordered_map<uint32_t, uint32_t> m_server_status_codes;
	unordered_map<uint32_t, uint32_t> m_client_status_codes;

private:
	void url_table_to_protobuf(draiosproto::proto_info* protobuf_msg, 
		unordered_map<string, sinsp_url_details>* table,
		bool is_server,
		uint32_t sampling_ratio);

	void status_code_table_to_protobuf(draiosproto::proto_info* protobuf_msg, 
		unordered_map<uint32_t, uint32_t>* table,
		bool is_server,
		uint32_t sampling_ratio);

	inline void mark_top_by(vector<unordered_map<string, sinsp_url_details>::iterator>* sortable_list, url_comparer comparer);

	//
	// Comparers for sorting
	//
	static bool cmp_ncalls(unordered_map<string, sinsp_url_details>::iterator src, unordered_map<string, sinsp_url_details>::iterator dst)
	{
		return src->second.m_ncalls > dst->second.m_ncalls;
	}

	static bool cmp_time_avg(unordered_map<string, sinsp_url_details>::iterator src, unordered_map<string, sinsp_url_details>::iterator dst)
	{
		return (src->second.m_time_tot / src->second.m_ncalls) > (dst->second.m_time_tot / dst->second.m_ncalls);
	}

	static bool cmp_time_max(unordered_map<string, sinsp_url_details>::iterator src, unordered_map<string, sinsp_url_details>::iterator dst)
	{
		return src->second.m_time_max > dst->second.m_time_max;
	}

	static bool cmp_bytes_tot(unordered_map<string, sinsp_url_details>::iterator src, unordered_map<string, sinsp_url_details>::iterator dst)
	{
		return (src->second.m_bytes_in + src->second.m_bytes_out) > 
			(dst->second.m_bytes_in + dst->second.m_bytes_out);
	}
};

#endif // HAS_ANALYZER
