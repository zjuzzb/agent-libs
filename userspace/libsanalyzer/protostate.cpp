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
// sinsp_proto_detector implementation
///////////////////////////////////////////////////////////////////////////////
inline void sinsp_protostate::mark_top_by(vector<unordered_map<string, sinsp_url_details>::iterator>* sortable_list,
						url_comparer comparer)
{
	uint32_t j;

	//
	// Mark top based on number of calls
	//
	partial_sort(sortable_list->begin(), 
		sortable_list->begin() + TOP_URLS_IN_SAMPLE, 
		sortable_list->end(),
		comparer);

	for(j = 0; j < TOP_URLS_IN_SAMPLE; j++)
	{
		sortable_list->at(j)->second.m_flags =
			(sinsp_url_details::udflags)((uint32_t)sortable_list->at(j)->second.m_flags | (uint32_t)sinsp_url_details::UF_INCLUDE_IN_SAMPLE);
	}
}

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

		//
		// Mark top based on number of calls
		//
		mark_top_by(&sortable_list, cmp_ncalls);
						
		//
		// Mark top based on total time
		//
		mark_top_by(&sortable_list, cmp_time_avg);

		//
		// Mark top based on max time
		//
		mark_top_by(&sortable_list, cmp_time_max);

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

			if((*vit)->second.m_flags & (uint32_t)sinsp_url_details::UF_INCLUDE_IN_SAMPLE)
			{
				ud->set_url((*vit)->first);
				ud->set_ncalls((*vit)->second.m_ncalls * sampling_ratio);
				ud->set_time_tot((*vit)->second.m_time_tot * sampling_ratio);
				ud->set_time_min((*vit)->second.m_time_min);
				ud->set_time_max((*vit)->second.m_time_max);
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
			ud->set_time_min(uit->second.m_time_min);
			ud->set_time_max(uit->second.m_time_max);
		}
	}
}

void sinsp_protostate::to_protobuf(draiosproto::proto_info* protobuf_msg, uint32_t sampling_ratio)
{
	if(m_server_urls.size() != 0)
	{
		url_table_to_protobuf(protobuf_msg, &m_server_urls, true, sampling_ratio);
	}

	if(m_client_urls.size() != 0)
	{
		url_table_to_protobuf(protobuf_msg, &m_client_urls, false, sampling_ratio);
	}
}

#endif // HAS_ANALYZER
