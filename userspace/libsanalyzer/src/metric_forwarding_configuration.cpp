#include "metric_forwarding_configuration.h"
#include "common_logger.h"
#include <Poco/Path.h>
#include <type_config.h>

COMMON_LOGGER();

namespace
{

/**
 * In the classic database (pre-meerkat), there is a limit of 
 * 3000 metrics per type. We also use this for any backends that 
 * don't have 10sFlush enabled. 
 */
const unsigned LEGACY_HARD_LIMIT = 3000;

int legacy_limiter(int configured)
{
	if (configured > LEGACY_HARD_LIMIT) 
	{
		return LEGACY_HARD_LIMIT;
	}

	return configured;
}

// This is no longer the way to turn on flexible limits. This is now negotiated
// between the agent and the backend. This is kept to support older backends.
type_config<bool>::ptr c_deprecated_enablement =
   type_config_builder<bool>(false /*default*/,
			     "Whether the limit for one type of metric can be "
			     "raised by lowering the limit for another type.",
			     "flexible_metric_limits",
			     "enabled")
	.hidden()
	.build();

type_config<int>::ptr c_prometheus_max =
   type_config_builder<int>(3000 /*default*/,
			    "The maximum number of prometheus metrics that will be reported to Sysdig Monitor.",
			    "prometheus",
			    "max_metrics")
	.min(0)
	.max(100000)
	.build();

type_config<int>::ptr c_statsd_max =
   type_config_builder<int>(100 /*default*/,
			    "The maximum number of statsd metrics that will be reported to Sysdig Monitor.",
			    "statsd",
			    "limit")
	.min(0)
	.max(10000)
	.build();

type_config<int>::ptr c_jmx_max =
   type_config_builder<int>(500 /*default*/,
			    "The maximum number of jmx metrics that will be reported to Sysdig Monitor.",
			    "jmx",
			    "limit")
	.min(0)
	.max(5000)
	.build();

type_config<int>::ptr c_app_checks_max =
   type_config_builder<int>(500 /*default*/,
			    "The maximum number of app checks metrics that will be reported to Sysdig Monitor.",
			    "app_checks_limit")
	.min(0)
	.max(5000)
	.build();

}

metric_forwarding_configuration metric_forwarding_configuration::s_instance;

metric_forwarding_configuration::metric_forwarding_configuration()
{
	// Boot with negotiation not supported to use previous scheme. This
	// is mostly for customers who have figured out (or were given) the
	// recipe of configs to force 10k mode without 10sFlush turned on.
	set_negotiated_value(negotiation_result::NEGOTIATION_NOT_SUPPORTED);
}

int metric_forwarding_configuration::configured_limit_sum()
{
	return c_prometheus_max->get_value() +
	       c_jmx_max->get_value() +
	       c_statsd_max->get_value() +
	       c_app_checks_max->get_value();
}

/**
 * The sum of all of the metrics must be below the
 * allowed_metric_sum. If they are not, then the max values are
 * dropped proportionally. Optionally, the limits can be raised
 * to fill up any available headroom.
 *
 * Returns the value which is used to change the given config to the allowed
 * config.
 */
float metric_forwarding_configuration::metric_divisor(int allowed_metric_sum)
{
	if(0 == allowed_metric_sum)
	{
		return 0;
	}

	float divisor = static_cast<float>(configured_limit_sum()) /
			static_cast<float>(allowed_metric_sum);

	// Only decrease limits. Don't increase them.
	if(divisor < 1.0)
	{
		return 1.0;
	}

	return divisor;
}

int metric_forwarding_configuration::calculate_limit(int configured_limit, int allowed_metric_sum)
{
	const float divisor = metric_divisor(allowed_metric_sum);
	if(0 == divisor)
	{
		return 0;
	}

	return static_cast<int>(configured_limit / divisor);
}

void metric_forwarding_configuration::set_negotiated_value(negotiation_result result, 
							   uint64_t negotiated_value)
{
	if (negotiation_result::USE_NEGOTIATED_VALUE == result)
	{
		// Ensure the metric limits don't add up to above the negotiated value
		LOG_INFO("Negotiated custom metric limit is %lu.", negotiated_value);
		m_prometheus_limit = calculate_limit(c_prometheus_max->get_value(), negotiated_value);
		m_statsd_limit = calculate_limit(c_statsd_max->get_value(), negotiated_value);
		m_jmx_limit = calculate_limit(c_jmx_max->get_value(), negotiated_value);
		m_app_checks_limit = calculate_limit(c_app_checks_max->get_value(), negotiated_value);
	}
	else if (negotiation_result::USE_LEGACY_LIMITS == result) 
	{
		if (!c_deprecated_enablement->get_value()) {
			LOG_INFO("Negotiated metric limit to 3k per metric type.");
			m_prometheus_limit = legacy_limiter(c_prometheus_max->get_value());
			m_statsd_limit = legacy_limiter(c_statsd_max->get_value());
			m_jmx_limit = legacy_limiter(c_jmx_max->get_value());
			m_app_checks_limit = legacy_limiter(c_app_checks_max->get_value());
		}
		else
		{
			// This is an invalid configuration; the backend would not have set 
			// this value and it is hidden from the logs. So this can only happen 
			// if someone manually read the dragent.auto.yaml file and copied the 
			// data into another configuration file.
			// Even though this is not allowed, we don't want to change functionality
			// without telling the customer, so warn then that we will remove this
			// functionality in the future.
			LOG_ERROR("The backend negotiation indicates that it cannot support a 10k "
			         "custom metric limit, but 'flexible_metric_limits.enabled: true' "
			         "is allowing a 10k limit. This is an invalid configuration and a "
				 "future version of the agent will automatically lower the limits.");
			const int pre_negotiation_sum = 10000;
			m_prometheus_limit = calculate_limit(c_prometheus_max->get_value(), pre_negotiation_sum);
			m_statsd_limit = calculate_limit(c_statsd_max->get_value(), pre_negotiation_sum);
			m_jmx_limit = calculate_limit(c_jmx_max->get_value(), pre_negotiation_sum);
			m_app_checks_limit = calculate_limit(c_app_checks_max->get_value(), pre_negotiation_sum);
		}
	}
	else // NEGOTIATION_NOT_SUPPORTED
	{
		// Prior to negotiation, going above legacy limits was controlled
		// by a config value and the only higher limit was 10k
		if(!c_deprecated_enablement->get_value())
		{
			LOG_INFO("Setting metric limit to 3k per metric type.");
			m_prometheus_limit = legacy_limiter(c_prometheus_max->get_value());
			m_statsd_limit = legacy_limiter(c_statsd_max->get_value());
			m_jmx_limit = legacy_limiter(c_jmx_max->get_value());
			m_app_checks_limit = legacy_limiter(c_app_checks_max->get_value());
		}
		else
		{
			LOG_INFO("Setting metric limit to a sum of 10k");
			const int pre_negotiation_sum = 10000;
			m_prometheus_limit = calculate_limit(c_prometheus_max->get_value(), pre_negotiation_sum);
			m_statsd_limit = calculate_limit(c_statsd_max->get_value(), pre_negotiation_sum);
			m_jmx_limit = calculate_limit(c_jmx_max->get_value(), pre_negotiation_sum);
			m_app_checks_limit = calculate_limit(c_app_checks_max->get_value(), pre_negotiation_sum);
		}
	}

	print();
}

void metric_forwarding_configuration::print()
{
	if (m_prometheus_limit != c_prometheus_max->get_value() ||
	    m_statsd_limit != c_statsd_max->get_value() ||
	    m_app_checks_limit != c_app_checks_max->get_value() ||
	    m_jmx_limit != c_jmx_max->get_value())
	{
		LOG_WARNING("Limits have been adjusted from the configured values.\n"
		            "Prometheus (%s): %d -> %d\n"
		            "StatsD (%s): %d -> %d\n"
		            "AppChecks (%s): %d -> %d\n"
		            "JMX (%s): %d -> %d",
		            c_prometheus_max->get_key_string().c_str(), c_prometheus_max->get_value(), m_prometheus_limit.load(),
		            c_statsd_max->get_key_string().c_str(), c_statsd_max->get_value(), m_statsd_limit.load(),
		            c_app_checks_max->get_key_string().c_str(), c_app_checks_max->get_value(), m_app_checks_limit.load(),
		            c_jmx_max->get_key_string().c_str(), c_jmx_max->get_value(), m_jmx_limit.load());
	}
	else
	{
		// These values already exist in the log, but print them out as a group
		// for supportability.
		LOG_INFO("Custom metric limits set to the following: "
		         "Prometheus (%s): %d\n"
		         "StatsD (%s): %d\n"
		         "AppChecks (%s): %d\n"
		         "JMX (%s): %d",
		         c_prometheus_max->get_key_string().c_str(), m_prometheus_limit.load(),
		         c_statsd_max->get_key_string().c_str(), m_statsd_limit.load(),
		         c_app_checks_max->get_key_string().c_str(), m_app_checks_limit.load(),
		         c_jmx_max->get_key_string().c_str(), m_jmx_limit.load());
	}
}

