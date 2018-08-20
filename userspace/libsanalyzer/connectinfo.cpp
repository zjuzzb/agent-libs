#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_int.h"
#include "analyzer.h"
#include "connectinfo.h"

#ifdef HAS_ANALYZER

sinsp_connection::sinsp_connection()
{
	m_timestamp = 0;
}

sinsp_connection::sinsp_connection(uint64_t timestamp)
{
	m_timestamp = timestamp;
}

void sinsp_connection::reset()
{
	m_spid = 0;
	m_stid = 0;
	m_sfd = 0;
	m_scomm = "";

	m_dpid = 0;
	m_dtid = 0;
	m_dfd = 0;
	m_dcomm = "";

	m_refcount = 0;
	m_timestamp = 0;
	m_analysis_flags = 0;
}

void sinsp_connection::reset_server()
{
	m_dpid = 0;
	m_dtid = 0;
	m_dfd = 0;
	m_dcomm = "";

	m_refcount = 1;
}

void sinsp_connection::reset_client()
{
	m_spid = 0;
	m_stid = 0;
	m_sfd = 0;
	m_scomm = "";

	m_refcount = 1;
}

bool sinsp_connection::is_client_only() const
{
	return 0 != m_stid && 0 == m_dtid;
}

bool sinsp_connection::is_server_only() const
{
	return 0 == m_stid && 0 != m_dtid;
}

bool sinsp_connection::is_client_and_server() const
{
	return 0 != m_stid && 0 != m_dtid;
}

void sinsp_connection::clear()
{
	m_metrics.clear();
	m_transaction_metrics.clear();
}

bool sinsp_connection::is_active() const
{
	uint32_t totops = m_metrics.m_client.m_count_in + m_metrics.m_client.m_count_out + 
				m_metrics.m_server.m_count_in + m_metrics.m_server.m_count_out;

	return (totops != 0);
}

void sinsp_connection_aggregator::clear()
{
	m_metrics.clear();
	m_transaction_metrics.clear();
	m_count = 0;
}

void sinsp_connection_aggregator::add(sinsp_connection* conn)
{
	m_metrics.add(&conn->m_metrics);
	m_transaction_metrics.add(&conn->m_transaction_metrics);
	++m_count;
}

void sinsp_connection_aggregator::add_client(sinsp_connection* conn)
{
	m_metrics.m_client.add(&conn->m_metrics.m_client);
	m_transaction_metrics.add(&conn->m_transaction_metrics);
	++m_count;
}

void sinsp_connection_aggregator::add_server(sinsp_connection* conn)
{
	m_metrics.m_server.add(&conn->m_metrics.m_server);
	m_transaction_metrics.add(&conn->m_transaction_metrics);
	++m_count;
}

void sinsp_connection_aggregator::to_protobuf(draiosproto::connection_categories *proto, uint32_t sampling_ratio) const
{
	m_metrics.to_protobuf(proto, sampling_ratio);
	m_transaction_metrics.to_protobuf(proto->mutable_transaction_counters(),
			proto->mutable_max_transaction_counters(),
			sampling_ratio);
	proto->set_n_aggregated_connections(m_count);
}

bool sinsp_connection_aggregator::operator<(const sinsp_connection_aggregator &other) const
{
	uint64_t tot = m_metrics.m_client.m_bytes_in +
				 m_metrics.m_client.m_bytes_out +
				 m_metrics.m_server.m_bytes_in +
				 m_metrics.m_server.m_bytes_out;

	uint64_t other_tot = other.m_metrics.m_client.m_bytes_in +
				 other.m_metrics.m_client.m_bytes_out +
				 other.m_metrics.m_server.m_bytes_in +
				 other.m_metrics.m_server.m_bytes_out;

	return tot < other_tot;
}
#endif // HAS_ANALYZER
