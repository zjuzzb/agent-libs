#include "sinsp.h"
#include "sinsp_int.h"
#include "connectinfo.h"

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
