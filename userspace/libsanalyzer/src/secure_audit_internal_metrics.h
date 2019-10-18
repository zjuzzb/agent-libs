#pragma once

class secure_audit_internal_metrics
{
public:
	virtual ~secure_audit_internal_metrics() = default;
	/// set_secure_audit_internal_metrics is an analyzer interface provided to secure_audit
	/// in order to be able to store internal metrics
	/// \param n_sent_protobufs
	/// \param flush_time_ms
	virtual void set_secure_audit_internal_metrics(int n_sent_protobufs,
						       uint64_t flush_time_ms) = 0;
};