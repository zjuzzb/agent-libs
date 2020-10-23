#include "secure_netsec_helper.ut.h"

// Metrics
secure_netsec_internal_metrics_dummy::secure_netsec_internal_metrics_dummy()
	: m_sent_protobufs(-1),
	  m_flush_time_ms(-1),
	  m_connection_dropped_count(-1),
	  m_connection_count(-1),
	  m_communication_invalid(-1),
	  m_communication_cidr_out(-1),
	  m_communication_cidr_in(-1),
	  m_communication_ingress_count(-1),
	  m_communication_egress_count(-1),
	  m_resolved_owner(-1)
{
}

int secure_netsec_internal_metrics_dummy::get_secure_netsec_n_sent_protobufs() const
{
	return m_sent_protobufs;
}

int secure_netsec_internal_metrics_dummy::get_secure_netsec_fl_ms() const
{
	return m_flush_time_ms;
}

int secure_netsec_internal_metrics_dummy::get_secure_netsec_connection_dropped_count() const
{
	return m_connection_dropped_count;
}

int secure_netsec_internal_metrics_dummy::get_secure_netsec_connection_count() const
{
	return m_connection_count;
}

int secure_netsec_internal_metrics_dummy::get_secure_netsec_communication_invalid() const
{
	return m_communication_invalid;
}

int secure_netsec_internal_metrics_dummy::get_secure_netsec_communication_cidr_in() const
{
	return m_communication_cidr_in;
}

int secure_netsec_internal_metrics_dummy::get_secure_netsec_communication_cidr_out() const
{
	return m_communication_cidr_out;
}

int secure_netsec_internal_metrics_dummy::get_secure_netsec_communication_ingress_count() const
{
	return m_communication_ingress_count;
}

int secure_netsec_internal_metrics_dummy::get_secure_netsec_communication_egress_count() const
{
	return m_communication_egress_count;
}

int secure_netsec_internal_metrics_dummy::get_secure_netsec_communication_resolved_owner() const
{
	return m_resolved_owner;
}

void secure_netsec_internal_metrics_dummy::set_secure_netsec_internal_metrics(int n_sent_protobufs,
									      uint64_t flush_time_ms)
{
	m_sent_protobufs = n_sent_protobufs;
	m_flush_time_ms = flush_time_ms;
}

void secure_netsec_internal_metrics_dummy::set_secure_netsec_sent_counters(
	int n_connection_dropped_count,
	int n_connection_count,
	int n_communication_invalid,
	int n_communication_cidr_out,
	int n_communication_cidr_in,
	int n_communication_ingress_count,
	int n_communication_egress_count,
	int n_resolved_owner)

{
	m_connection_dropped_count = n_connection_dropped_count;
	m_connection_count = n_connection_count;
	m_communication_invalid = n_communication_invalid;
	m_communication_cidr_out = n_communication_cidr_out;
	m_communication_cidr_in = n_communication_cidr_in;
	m_communication_ingress_count = n_communication_ingress_count;
	m_communication_egress_count = n_communication_egress_count;
	m_resolved_owner = n_resolved_owner;
}

// Data handler
secure_netsec_data_ready_dummy::secure_netsec_data_ready_dummy() :
	m_secure_netsec_summary(nullptr),
	m_ts(0)
{
}

void secure_netsec_data_ready_dummy::secure_netsec_data_ready(uint64_t ts,
							      const secure::K8SCommunicationSummary* secure_netsec_summary)
{
	m_ts = ts;
	m_secure_netsec_summary_copy = *secure_netsec_summary;
	m_secure_netsec_summary = &m_secure_netsec_summary_copy;
}

const secure::K8SCommunicationSummary* secure_netsec_data_ready_dummy::get_secure_netsec_summary_once()
{
	const secure::K8SCommunicationSummary* ret = m_secure_netsec_summary;
	m_secure_netsec_summary = nullptr;
	return ret;
}

uint64_t secure_netsec_data_ready_dummy::get_ts_once()
{
	uint64_t ret = m_ts;
	m_ts = 0;
	return ret;
}
