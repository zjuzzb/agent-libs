#pragma once

#include <secure_netsec.h>
#include "secure_netsec_data_ready_handler.h"

// dummy implementation used for testing
class secure_netsec_internal_metrics_dummy : public secure_netsec_internal_metrics
{
public:
	secure_netsec_internal_metrics_dummy();
	void set_secure_netsec_internal_metrics(int n_sent_protobufs, uint64_t flush_time_ms) override;
	void set_secure_netsec_sent_counters(int m_connection_dropped_count,
					     int m_connection_count,
					     int m_communication_invalid,
					     int m_communication_cidr_out,
					     int m_communication_cidr_in,
					     int m_communication_ingress_count,
					     int m_communication_egress_count,
					     int m_resolved_owner) override;

	int get_secure_netsec_n_sent_protobufs() const;
	int get_secure_netsec_fl_ms() const;

	int get_secure_netsec_connection_dropped_count() const;
	int get_secure_netsec_connection_count() const;
	int get_secure_netsec_communication_invalid() const;
	int get_secure_netsec_communication_cidr_out() const;
	int get_secure_netsec_communication_cidr_in() const;
	int get_secure_netsec_communication_ingress_count() const;
	int get_secure_netsec_communication_egress_count() const;
	int get_secure_netsec_communication_resolved_owner() const;

private:
	int m_sent_protobufs;
	uint64_t m_flush_time_ms;
	int m_connection_dropped_count;
	int m_connection_count;
	int m_communication_invalid;
	int m_communication_cidr_out;
	int m_communication_cidr_in;
	int m_communication_ingress_count;
	int m_communication_egress_count;
	int m_resolved_owner;
};

// dummy implementation used for testing
class secure_netsec_data_ready_dummy : public secure_netsec_data_ready_handler
{
public:
	secure_netsec_data_ready_dummy();
	void secure_netsec_data_ready(uint64_t ts, const secure::K8SCommunicationSummary* secure_netsec_summary) override;

	const secure::K8SCommunicationSummary* get_secure_netsec_summary_once();
	uint64_t get_ts_once();

private:
	const secure::K8SCommunicationSummary* m_secure_netsec_summary;
	secure::K8SCommunicationSummary m_secure_netsec_summary_copy;
	uint64_t m_ts;
};
