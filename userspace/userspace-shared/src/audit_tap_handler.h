#pragma once

namespace tap {
class AuditLog;
}

/**
 * virtual class that defines the API invoked when audit tap data is ready. Courtesy default
 * implementations are provided.
 */

class audit_tap_handler
{
public:
	virtual void audit_tap_data_ready(uint64_t ts_ns, const tap::AuditLog *audit_log) = 0;
};

class audit_tap_handler_dummy : public audit_tap_handler
{
public:
	virtual void audit_tap_data_ready(uint64_t ts_ns, const tap::AuditLog *audit_log)
	{
	}
};

