#pragma once

namespace secure
{
class Audit;
}

class secure_audit_handler
{
public:
	virtual void secure_audit_data_ready(uint64_t ts_ns, const secure::Audit *secure_audit) = 0;
};

/**
 * virtual class that defines the API invoked when secure audit data is ready. Courtesy default
 * implementations are provided.
 */
class null_secure_audit_handler : public secure_audit_handler
{
public:
	void secure_audit_data_ready(uint64_t ts_ns, const secure::Audit *secure_audit) override
	{
	}
};
