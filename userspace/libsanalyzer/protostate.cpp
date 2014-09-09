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
	unordered_map<string, sinsp_url_details>::iterator uit;

	if(m_server_urls.size() != 0)
	{
		draiosproto::url_details* ud = protobuf_msg->mutable_http()->add_server_urls();

		for(uit = m_server_urls.begin(); uit != m_server_urls.end(); ++uit)
		{
			ud->set_url(uit->first);
			ud->set_ncalls(uit->second.m_ncalls);
			ud->set_time_tot(uit->second.m_time_tot);
			ud->set_time_min(uit->second.m_time_min);
			ud->set_time_max(uit->second.m_time_max);
		}
	}

	if(m_client_urls.size() != 0)
	{
		draiosproto::url_details* ud = protobuf_msg->mutable_http()->add_client_urls();

		for(uit = m_client_urls.begin(); uit != m_client_urls.end(); ++uit)
		{
			ud->set_url(uit->first);
			ud->set_ncalls(uit->second.m_ncalls);
			ud->set_time_tot(uit->second.m_time_tot);
			ud->set_time_min(uit->second.m_time_min);
			ud->set_time_max(uit->second.m_time_max);
		}
	}
}

#endif // HAS_ANALYZER
