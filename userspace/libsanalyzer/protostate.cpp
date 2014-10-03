#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

#include "sinsp.h"
#include "sinsp_int.h"

#ifdef HAS_ANALYZER
#include "analyzer_int.h"
#include "analyzer.h"
#include "analyzer_int.h"
#include "parser_http.h"
#include "metrics.h"
#include "draios.pb.h"
#include "protostate.h"

///////////////////////////////////////////////////////////////////////////////
// Transaction table update support
///////////////////////////////////////////////////////////////////////////////
inline void sinsp_protostate::update_http(sinsp_partial_transaction* tr, 
						uint64_t time_delta, bool is_server)
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

		request_sorter<sinsp_url_details>::update(entry, tr, time_delta);

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

inline void sinsp_protostate::update_mysql(sinsp_partial_transaction* tr, 
						uint64_t time_delta, bool is_server)
{
	ASSERT(tr->m_protoparser != NULL);

	if(tr->m_protoparser->m_is_valid)
	{
		sinsp_mysql_parser* pp = (sinsp_mysql_parser*)tr->m_protoparser;

		//
		// Update the query table
		//
		sinsp_query_details* entry;

		if(is_server)
		{
			entry = &(m_server_queries[pp->m_statement]);
		}
		else
		{
			entry = &(m_client_queries[pp->m_statement]);
		}

		if(entry->m_ncalls == 0)
		{
			entry->m_ncalls = 1;
			entry->m_time_tot = time_delta;
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

			if(time_delta > entry->m_time_max)
			{
				entry->m_time_max = time_delta;
			}
		}

		//
		// Update the status code table
		//
/*
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
*/
	}
}

void sinsp_protostate::update(sinsp_partial_transaction* tr,
	uint64_t time_delta,
	bool is_server)
{
	if(tr->m_type == sinsp_partial_transaction::TYPE_HTTP)
	{
		update_http(tr, time_delta, is_server);
	}
	else if(tr->m_type == sinsp_partial_transaction::TYPE_MYSQL)
	{
//		update_mysql(tr, time_delta, is_server);
	}
}

///////////////////////////////////////////////////////////////////////////////
// Aggregation support
///////////////////////////////////////////////////////////////////////////////
inline void sinsp_protostate::add_http(sinsp_protostate* other)
{
	//
	// Add the URLs
	//
	request_sorter<sinsp_url_details>::merge_maps(&m_server_urls, &(other->m_server_urls));
	request_sorter<sinsp_url_details>::merge_maps(&m_client_urls, &(other->m_client_urls));

	//
	// Add the status codes
	//
	unordered_map<uint32_t, uint32_t>::iterator scit;
	unordered_map<uint32_t, uint32_t>::iterator scit1;
	unordered_map<uint32_t, uint32_t>* psc;

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

inline void sinsp_protostate::add_mysql(sinsp_protostate* other)
{
}

void sinsp_protostate::add(sinsp_protostate* other)
{
	add_http(other);
	add_mysql(other);
}

///////////////////////////////////////////////////////////////////////////////
// Protobuf generation
///////////////////////////////////////////////////////////////////////////////
void sinsp_protostate::url_table_to_protobuf(draiosproto::proto_info* protobuf_msg, 
						   unordered_map<string, sinsp_url_details>* table,
						   bool is_server,
						   uint32_t sampling_ratio)
{
	uint32_t j;
	unordered_map<string, sinsp_url_details>::iterator uit;
	draiosproto::url_details* ud;

	if(table->size() > TOP_URLS_IN_SAMPLE)
	{
		//
		// The table is big enough to require sorting
		//
		vector<unordered_map<string, sinsp_url_details>::iterator> sortable_list;
		vector<unordered_map<string, sinsp_url_details>::iterator>::iterator vit;

		for(uit = table->begin(); uit != table->end(); ++uit)
		{
			sortable_list.push_back(uit);
		}

		request_sorter<sinsp_url_details>::mark_top(&sortable_list);

		//
		// Go through the list and emit the marked elements
		//
		for(vit = sortable_list.begin(), j = 0; vit != sortable_list.end() && j < TOP_URLS_IN_SAMPLE; ++vit, ++j)
		{
			if(is_server)
			{
				ud = protobuf_msg->mutable_http()->add_server_urls();
			}
			else
			{
				ud = protobuf_msg->mutable_http()->add_client_urls();
			}

			if((*vit)->second.m_flags & (uint32_t)SRF_INCLUDE_IN_SAMPLE)
			{
				ud->set_url((*vit)->first);
				ud->set_ncalls((*vit)->second.m_ncalls * sampling_ratio);
				ud->set_time_tot((*vit)->second.m_time_tot * sampling_ratio);
				ud->set_time_max((*vit)->second.m_time_max);
				ud->set_bytes_in((*vit)->second.m_bytes_in);
				ud->set_bytes_out((*vit)->second.m_bytes_out);
			}
		}
	}
	else
	{
		//
		// The table is small enough that we don't need to sort it
		//
		for(uit = table->begin(); uit != table->end(); ++uit)
		{
			if(is_server)
			{
				ud = protobuf_msg->mutable_http()->add_server_urls();
			}
			else
			{
				ud = protobuf_msg->mutable_http()->add_client_urls();
			}

			ud->set_url(uit->first);
			ud->set_ncalls(uit->second.m_ncalls * sampling_ratio);
			ud->set_time_tot(uit->second.m_time_tot * sampling_ratio);
			ud->set_time_max(uit->second.m_time_max);
			ud->set_bytes_in(uit->second.m_bytes_in);
			ud->set_bytes_out(uit->second.m_bytes_out);
		}
	}
}

void sinsp_protostate::status_code_table_to_protobuf(draiosproto::proto_info* protobuf_msg, 
	unordered_map<uint32_t, uint32_t>* table,
	bool is_server,
	uint32_t sampling_ratio)
{
	uint32_t j;
	unordered_map<uint32_t, uint32_t>::iterator uit;
	draiosproto::status_code_details* ud;

	if(table->size() > TOP_STATUS_CODES_IN_SAMPLE)
	{
		//
		// The table is big enough to require sorting
		//
		vector<pair<uint32_t, uint32_t>> sortable_list;
		vector<pair<uint32_t, uint32_t>>::iterator vit;

		for(uit = table->begin(); uit != table->end(); ++uit)
		{
			sortable_list.push_back(pair<uint32_t, uint32_t>(uit->second, uit->first));
		}

		partial_sort(sortable_list.rbegin(), 
			sortable_list.rbegin() + TOP_STATUS_CODES_IN_SAMPLE, 
			sortable_list.rend());

		//
		// Go through the list and emit the marked elements
		//
		for(vit = sortable_list.begin(), j = 0; j < TOP_STATUS_CODES_IN_SAMPLE; ++vit, ++j)
		{
			if(is_server)
			{
				ud = protobuf_msg->mutable_http()->add_server_status_codes();
			}
			else
			{
				ud = protobuf_msg->mutable_http()->add_client_status_codes();
			}

			ud->set_status_code(vit->second);
			ud->set_ncalls(vit->first * sampling_ratio);
		}
	}
	else
	{
		//
		// The table is small enough that we don't need to sort it
		//
		for(uit = table->begin(); uit != table->end(); ++uit)
		{
			if(is_server)
			{
				ud = protobuf_msg->mutable_http()->add_server_status_codes();
			}
			else
			{
				ud = protobuf_msg->mutable_http()->add_client_status_codes();
			}

			ud->set_status_code(uit->first);
			ud->set_ncalls(uit->second * sampling_ratio);
		}
	}
}

void sinsp_protostate::query_table_to_protobuf(draiosproto::proto_info* protobuf_msg, 
						   unordered_map<string, sinsp_query_details>* table,
						   bool is_server,
						   uint32_t sampling_ratio)
{
}

void sinsp_protostate::to_protobuf(draiosproto::proto_info* protobuf_msg, uint32_t sampling_ratio)
{
	//
	// HTTP
	//
	if(m_server_urls.size() != 0)
	{
		url_table_to_protobuf(protobuf_msg, &m_server_urls, true, sampling_ratio);
	}

	if(m_client_urls.size() != 0)
	{
		url_table_to_protobuf(protobuf_msg, &m_client_urls, false, sampling_ratio);
	}

	if(m_server_status_codes.size() != 0)
	{
		status_code_table_to_protobuf(protobuf_msg, &m_server_status_codes, true, sampling_ratio);
	}

	if(m_client_status_codes.size() != 0)
	{
		status_code_table_to_protobuf(protobuf_msg, &m_client_status_codes, false, sampling_ratio);
	}

	//
	// mysql
	//
	if(m_server_queries.size() != 0)
	{
		query_table_to_protobuf(protobuf_msg, &m_server_queries, true, sampling_ratio);
	}

	if(m_client_queries.size() != 0)
	{
		query_table_to_protobuf(protobuf_msg, &m_client_queries, false, sampling_ratio);
	}
}

#endif // HAS_ANALYZER
