#pragma once

namespace secure
{
	namespace profiling
	{
		class fingerprint;
	}
}

class secure_profiling_handler
{
public:
	virtual void secure_profiling_data_ready(uint64_t ts_ns, const secure::profiling::fingerprint *fingerprint) = 0;
};

/**
 * virtual class that defines the API invoked when secure audit data is ready. Courtesy default
 * implementations are provided.
 */
class null_secure_profiling_handler : public secure_profiling_handler
{
public:
	void secure_profiling_data_ready(uint64_t ts_ns, const secure::profiling::fingerprint *fingerprint) override
	{
	}
};
