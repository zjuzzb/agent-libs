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
void sinsp_protostate::to_protobuf(draiosproto::proto_info* protobuf_msg, uint32_t sampling_ratio)
{
	uint32_t j;
	unordered_map<string, sinsp_url_details>::iterator uit;

	if(m_server_urls.size() > TOP_URLS_IN_SAMPLE)
	{
		vector<unordered_map<string, sinsp_url_details>::iterator> sortable_list;
		vector<unordered_map<string, sinsp_url_details>::iterator>::iterator vit;

		for(uit = m_server_urls.begin(); uit != m_server_urls.end(); ++uit)
		{
			sortable_list.push_back(uit);
		}

		partial_sort(sortable_list.begin(), 
			sortable_list.begin() + TOP_URLS_IN_SAMPLE, 
			sortable_list.end(),
			cmp_ncalls);

		for(vit = sortable_list.begin(), j = 0; vit != sortable_list.end() && j < TOP_URLS_IN_SAMPLE; ++vit, ++j)
		{
			draiosproto::url_details* ud = protobuf_msg->mutable_http()->add_server_urls();

			ud->set_url((*vit)->first);
			ud->set_ncalls((*vit)->second.m_ncalls);
			ud->set_time_tot((*vit)->second.m_time_tot);
			ud->set_time_min((*vit)->second.m_time_min);
			ud->set_time_max((*vit)->second.m_time_max);
		}
	}
	else if(m_server_urls.size() != 0)
	{
		for(uit = m_server_urls.begin(); uit != m_server_urls.end(); ++uit)
		{
			draiosproto::url_details* ud = protobuf_msg->mutable_http()->add_server_urls();

			ud->set_url(uit->first);
			ud->set_ncalls(uit->second.m_ncalls);
			ud->set_time_tot(uit->second.m_time_tot);
			ud->set_time_min(uit->second.m_time_min);
			ud->set_time_max(uit->second.m_time_max);
		}
	}

	if(m_client_urls.size() > TOP_URLS_IN_SAMPLE)
	{
		vector<unordered_map<string, sinsp_url_details>::iterator> sortable_list;
		vector<unordered_map<string, sinsp_url_details>::iterator>::iterator vit;

		for(uit = m_client_urls.begin(); uit != m_client_urls.end(); ++uit)
		{
			sortable_list.push_back(uit);
		}

		partial_sort(sortable_list.begin(), 
			sortable_list.begin() + TOP_URLS_IN_SAMPLE, 
			sortable_list.end(),
			cmp_ncalls);

		for(vit = sortable_list.begin(), j = 0; vit != sortable_list.end() && j < TOP_URLS_IN_SAMPLE; ++vit, ++j)
		{
			draiosproto::url_details* ud = protobuf_msg->mutable_http()->add_client_urls();

			ud->set_url((*vit)->first);
			ud->set_ncalls((*vit)->second.m_ncalls);
			ud->set_time_tot((*vit)->second.m_time_tot);
			ud->set_time_min((*vit)->second.m_time_min);
			ud->set_time_max((*vit)->second.m_time_max);
		}
	}
	else if(m_client_urls.size() != 0)
	{
		for(uit = m_client_urls.begin(); uit != m_client_urls.end(); ++uit)
		{
			draiosproto::url_details* ud = protobuf_msg->mutable_http()->add_client_urls();

			ud->set_url(uit->first);
			ud->set_ncalls(uit->second.m_ncalls);
			ud->set_time_tot(uit->second.m_time_tot);
			ud->set_time_min(uit->second.m_time_min);
			ud->set_time_max(uit->second.m_time_max);
		}
	}
}

#endif // HAS_ANALYZER
