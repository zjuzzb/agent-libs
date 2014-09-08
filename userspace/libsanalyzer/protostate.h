#ifdef HAS_ANALYZER

#pragma once

#include "parser_http.h"
#include "transactinfo.h"

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
				sinsp_url_info* entry;

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
				}
				else
				{
					entry->m_ncalls++;
					entry->m_time_tot += time_delta;
					entry->m_time_min += time_delta;
					entry->m_time_max += time_delta;
				}
			}
		}
	}

	inline void clear()
	{
		m_client_urls.clear();
		m_server_urls.clear();
	}

	void add(sinsp_protostate* other)
	{
		unordered_map<string, sinsp_url_info>::iterator uit;
		unordered_map<string, sinsp_url_info>* pom;

		//
		// Add the server URLs
		//
		pom = &(other->m_server_urls);

		for(uit = pom->begin(); uit != pom->end(); ++uit)
		{
			//sinsp_url_info* entry = &(uit->second);

			sinsp_url_info* entry = &(m_server_urls[uit->first]);

			if(entry->m_ncalls == 0)
			{
				*entry = uit->second;
			}
			else
			{
				entry->m_ncalls += uit->second.m_ncalls;
				entry->m_time_tot += uit->second.m_time_tot;
				entry->m_time_min += uit->second.m_time_min;
				entry->m_time_max += uit->second.m_time_max;
			}
		}

		//
		// Add the client URLs
		//
		pom = &(other->m_client_urls);

		for(uit = pom->begin(); uit != pom->end(); ++uit)
		{
			//sinsp_url_info* entry = &(uit->second);

			sinsp_url_info* entry = &(m_client_urls[uit->first]);

			if(entry->m_ncalls == 0)
			{
				*entry = uit->second;
			}
			else
			{
				entry->m_ncalls += uit->second.m_ncalls;
				entry->m_time_tot += uit->second.m_time_tot;
				entry->m_time_min += uit->second.m_time_min;
				entry->m_time_max += uit->second.m_time_max;
			}
		}
	}

	// The list of URLs
	unordered_map<string, sinsp_url_info> m_server_urls;
	unordered_map<string, sinsp_url_info> m_client_urls;
};

#endif // HAS_ANALYZER
