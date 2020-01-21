#pragma once

namespace secure
{
class Audit;
}

class secure_audit_data_ready_handler
{
public:
	virtual ~secure_audit_data_ready_handler() = default;
	/// secure_audit_data_ready is an analyzer interface provided to secure_audit
	/// in order to call secure_audit_handler
	/// \param ts
	/// \param secure_audits
	virtual void secure_audit_data_ready(uint64_t ts, const secure::Audit* secure_audits) = 0;
};
