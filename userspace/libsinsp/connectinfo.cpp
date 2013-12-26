#include "sinsp.h"
#include "sinsp_int.h"
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

bool sinsp_connection::is_client_only()
{
	return 0 != m_stid && 0 == m_dtid;
}

bool sinsp_connection::is_server_only()
{
	return 0 == m_stid && 0 != m_dtid;
}

bool sinsp_connection::is_client_and_server()
{
	return 0 != m_stid && 0 != m_dtid;
}

void sinsp_connection::clear()
{
	m_metrics.clear();
	m_transaction_metrics.clear();
}

bool sinsp_connection::is_active()
{
	uint32_t totops = m_metrics.m_client.m_count_in + m_metrics.m_client.m_count_out + 
				m_metrics.m_server.m_count_in + m_metrics.m_server.m_count_out;

	return (totops != 0);
}

#endif // HAS_ANALYZER
