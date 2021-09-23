#include <functional>
#include <memory>
#include <string>

#include "analyzer_utils.h"
#include "prom_grpc.h"
#include "prom_helper.h"
#include "common_logger.h"
#include "type_config.h"
#include "utils.h"
#include "sinsp.h"

COMMON_LOGGER();

/**
 * Uses the coclient interface to create a unary connection.
 *
 * See prom_unarygrpc_iface::start_unary_connection() for more
 * info.
 *
 */
bool prom_unarygrpc::start_unary_connection(int64_t boot_ts, std::shared_ptr<agent_promscrape::Config>& config, resp_cb_t response_cb)
{
	LOG_INFO("opening GRPC connection to %s", m_sock.c_str());
	grpc::ChannelArguments args;
	// Set maximum receive message size to unlimited
	args.SetMaxReceiveMessageSize(-1);
	if ((!m_config_conn))
	{
		m_config_conn = grpc_connect<agent_promscrape::ScrapeService::Stub>(m_sock, 10, &args);
		if (!m_config_conn) {
			if (prom_helper::elapsed_s(boot_ts, sinsp_utils::get_current_time_ns()) < 30)
			{
				LOG_INFO("failed to connect to %s, retrying in %ds", m_sock.c_str(),
					prom_helper::c_promscrape_connect_interval.get_value());
			}
			else
			{
				LOG_ERROR("failed to connect to %s, retrying in %ds", m_sock.c_str(),
					prom_helper::c_promscrape_connect_interval.get_value());
			}
			return false;
		}
	}
	
	m_grpc_applyconfig = make_unique<unary_grpc_client(&agent_promscrape::ScrapeService::Stub::AsyncApplyConfig)>(m_config_conn);
	m_grpc_applyconfig->do_rpc(*config, response_cb);
	return true;
}

/**
 * See prom_unarygrpc_iface::reset() for more info
 * 
 */
void prom_unarygrpc::reset()
{
	m_config_conn = nullptr;
	m_grpc_applyconfig = nullptr;
}

/**
 * Uses the coclient interface for processing response queue.
 *
 * See prom_unarygrpc_iface::process_queue() for more info
 *
 */
void prom_unarygrpc::process_queue()
{
	if (m_grpc_applyconfig)
	{
		(void) m_grpc_applyconfig->process_queue();
	}
}

/**
 * Uses the coclient interface for starting a stream connection.
 *
 * See prom_streamgrpc_iface::start_stream_connection() for more
 * info.
 *
 */
void prom_streamgrpc::start_stream_connection(int64_t boot_ts, resp_cb_t response_cb)
{
	agent_promscrape::Empty empty;
	if (!m_start_conn) {
		LOG_INFO("opening GRPC connection to %s", m_sock.c_str());
		grpc::ChannelArguments args;
		// Set maximum receive message size to unlimited
		args.SetMaxReceiveMessageSize(-1);

		m_start_conn = grpc_connect<agent_promscrape::ScrapeService::Stub>(m_sock, 10, &args);
		if (!m_start_conn) {
			// Only log at error if we've been up for a while
			if (prom_helper::elapsed_s(boot_ts, sinsp_utils::get_current_time_ns()) < 30)
			{
				LOG_INFO("failed to connect to %s, retrying in %ds", m_sock.c_str(),
					prom_helper::c_promscrape_connect_interval.get_value());
			}
			else
			{
				LOG_ERROR("failed to connect to %s, retrying in %ds", m_sock.c_str(),
					prom_helper::c_promscrape_connect_interval.get_value());
			}
			return;
		}
	}
	m_grpc_start = make_unique<streaming_grpc_client(&agent_promscrape::ScrapeService::Stub::AsyncGetData)>(m_start_conn);
	m_grpc_start->do_rpc(empty, response_cb);
}

/**
 * See prom_streamgrpc_iface::started() for more info
 *
 */
bool prom_streamgrpc::started() 
{
	return m_grpc_start != nullptr;
}

/**
 * See prom_streamgrpc_iface::reset() for more info
 *
 */
void prom_streamgrpc::reset()
{
	m_grpc_start = nullptr;
	m_start_conn = nullptr;
}

/**
 * See prom_streamgrpc_iface::process_queue() for more info
 *
 */
void prom_streamgrpc::process_queue()
{
	if (m_grpc_start)
	{
		(void) m_grpc_start->process_queue();
	}
}

