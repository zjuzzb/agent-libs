#pragma once

#include <atomic>

/**
 * Control all of the metric limits for the prometheus, jmx, 
 *  
 * During the metrics handshake, the backend and agent 
 * negotiate how many custom metrics are allowed to come from 
 * the agent in every 10s packet. This class reacts to that 
 * negotiation and updates the limits appropriately.  
 */
class metric_forwarding_configuration
{

public:
	metric_forwarding_configuration();

	static metric_forwarding_configuration& instance()
	{
		return s_instance;
	}

	enum class negotiation_result
	{
		NEGOTIATION_NOT_SUPPORTED,
		USE_LEGACY_LIMITS,
		USE_NEGOTIATED_VALUE
	};
	void set_negotiated_value(negotiation_result result, uint64_t negotiated_value = 0);

	/**
	 * The agent and backend negotiate what the metric limit is. If 
	 * this is different from the configured sum then override it. 
	 */
	void override_sum(uint64_t sum);


	/**
	 * Accessor to retrieve the prometheus limit. This value is 
	 * configurable but it can change after the backend handshake. 
	 * This accessor is thread-safe. 
	 */
	int prometheus_limit()
	{
		return m_prometheus_limit;
	}

	/**
	 * Accessor to retrieve the statsd limit. This value is 
	 * configurable but it can change after the backend handshake. 
	 * This accessor is thread-safe. 
	 */
	int statsd_limit()
	{
		return m_statsd_limit;
	}

	/**
	 * Accessor to retrieve the jmx limit. This value is 
	 * configurable but it can change after the backend handshake. 
	 * This accessor is thread-safe. 
	 */
	int jmx_limit()
	{
		return m_jmx_limit;
	}

	/**
	 * Accessor to retrieve the app_checks limit. This value is 
	 * configurable but it can change after the backend handshake. 
	 * This accessor is thread-safe. 
	 */
	int app_checks_limit()
	{
		return m_app_checks_limit;
	}

	/**
	 * Print helpful information about the config.
	 */
	void print();

private:

	float metric_divisor(int allowed_metric_sum);
	int calculate_limit(int configured_limit, int allowed_metric_sum);
	int configured_limit_sum();

	std::atomic<int> m_prometheus_limit;
	std::atomic<int> m_statsd_limit;
	std::atomic<int> m_jmx_limit;
	std::atomic<int> m_app_checks_limit;

	static metric_forwarding_configuration s_instance;
};
