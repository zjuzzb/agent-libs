#include "metric_forwarding_configuration.h"
#include <logger.h>
#include <Poco/Path.h>
#include <type_config.h>

namespace
{

const unsigned LEGACY_PROM_METRICS_HARD_LIMIT = 3000;
const unsigned LEGACY_STATSD_METRIC_HARD_LIMIT = 3000;
const unsigned LEGACY_APP_METRICS_HARD_LIMIT = 3000;
const unsigned LEGACY_JMX_METRICS_HARD_LIMIT = 3000;
const unsigned TEN_K_LIMIT = 10000;


// When this is released on an external agent, the metric_forwarding_limit
// should just be raised to 100k and this should be deleted. Alternatively,
// the idea of "give limits from one type to another" could just go away.
type_config<bool>::ptr c_enable_100k =
   type_config_builder<bool>(false /*default*/,
			     "Internal config to test 100k metrics",
			     "flexible_metric_limits",
			     "sysdig_test_100k_prom")
	.hidden()
	.mutable_only_in_internal_build()
	.build();

// Legacy backends don't support the number of metrics that the customer will
// be able to send with this config.  Default to off and allow the backend to
// turn it on.
type_config<bool>::ptr c_enabled =
   type_config_builder<bool>(false /*default*/,
			     "Whether the limit for one type of metric can be "
			     "raised by lowering the limit for another type.",
			     "flexible_metric_limits",
			     "enabled")
	.hidden()
	.build();

type_config<int>::ptr c_metric_forwarding_sum =
   type_config_builder<int>(10000 /*default*/,
			    "The maximum total of all prometheus, jmx, statsd "
			    "and app check metrics.",
			    "metric_forwarding_limit")
	.min(0)
	.max(100000)
	.post_init([](type_config<int>& config)
	{
		if (!c_enable_100k->configured() && 
		    config.configured() > TEN_K_LIMIT)
		{
			// invalid value, drop to TEN_K_LIMIT
			config.get_value() = TEN_K_LIMIT;
		}

	})
	.hidden()
	.build();

type_config<bool>::ptr c_fill_metric_headroom =
   type_config_builder<bool>(true /*default*/,
			     "Whether to automatically raise metric limits "
			     "proportionally to send the maximum allowed number "
			     "of metrics",
			     "flexible_metric_limits",
			     "fill_headroom")
	.hidden()
	.build();

int configured_limit_sum()
{
	return metric_forwarding_configuration::c_prometheus_max->configured() +
	       metric_forwarding_configuration::c_jmx_max->configured() +
	       metric_forwarding_configuration::c_statsd_max->configured() +
	       metric_forwarding_configuration::c_app_checks_max->configured();
}

/**
 * The sum of all of the metrics must be below the c_metric_forwarding_sum.
 * If they are not, then the max values are dropped proportionally.
 * Optionally, the limits can be raised to fill up any available headroom.
 *
 * Returns the value which is used to change the given config to the allowed
 * config.
 */
float metric_divisor()
{
	if(0 == c_metric_forwarding_sum->get_value())
	{
		return 0;
	}


	float divisor = static_cast<float>(configured_limit_sum()) /
			static_cast<float>(c_metric_forwarding_sum->configured());

	if((!c_fill_metric_headroom->get_value()) && divisor < 1.0)
	{
		return 1.0;
	}

	return divisor;
}

void adjust_limit(int& limit, const int legacy_hard_limit)
{
	if(!c_enabled->get_value())
	{
		limit =  limit < legacy_hard_limit ?
		   limit : legacy_hard_limit;
		return;
	}

	const float divisor = metric_divisor();
	if(0 == divisor)
	{
		limit = 0;
		return;
	}

	limit = limit / divisor;
}

}

namespace metric_forwarding_configuration
{

type_config<int>::ptr c_prometheus_max =
   type_config_builder<int>(3000 /*default*/,
			    "The maximum number of prometheus metrics that will be reported to Sysdig Monitor.",
			    "prometheus",
			    "max_metrics")
	.min(0)
	.max(100000)
	.post_init([](type_config<int>& config)
	{
		adjust_limit(config.get_value(), LEGACY_PROM_METRICS_HARD_LIMIT);
	})
	.build();

type_config<int>::ptr c_statsd_max =
   type_config_builder<int>(100 /*default*/,
			    "The maximum number of statsd metrics that will be reported to Sysdig Monitor.",
			    "statsd",
			    "limit")
	.min(0)
	.max(10000)
	.post_init([](type_config<int>& config)
	{
		adjust_limit(config.get_value(), LEGACY_STATSD_METRIC_HARD_LIMIT);
	})
	.build();

type_config<int>::ptr c_jmx_max =
   type_config_builder<int>(500 /*default*/,
			    "The maximum number of jmx metrics that will be reported to Sysdig Monitor.",
			    "jmx",
			    "limit")
	.min(0)
	.max(5000)
	.post_init([](type_config<int>& config)
	{
		adjust_limit(config.get_value(), LEGACY_JMX_METRICS_HARD_LIMIT);
	})
	.build();

type_config<int>::ptr c_app_checks_max =
   type_config_builder<int>(500 /*default*/,
			    "The maximum number of app checks metrics that will be reported to Sysdig Monitor.",
			    "app_checks_limit")
	.min(0)
	.max(5000)
	.post_init([](type_config<int>& config)
	{
		adjust_limit(config.get_value(), LEGACY_APP_METRICS_HARD_LIMIT);
	})
	.build();


void print()
{
	if(!c_enabled->get_value())
	{
		return;
	}

	if (c_prometheus_max->get_value() != c_prometheus_max->configured() ||
	    c_statsd_max->get_value() != c_statsd_max->configured() ||
	    c_app_checks_max->get_value() != c_app_checks_max->configured() ||
	    c_jmx_max->get_value() != c_jmx_max->configured())
	{
		SINSP_WARNING("%s:%d: Limits have been adjusted.\n"
			      "Your total allowed metric limit is %d per agent sample for this node, but it is currently configured to %d. The limits have been adjusted as follows:\n"
			      "Prometheus (%s): %d -> %d\n"
			      "StatsD (%s): %d -> %d\n"
			      "AppChecks (%s): %d -> %d\n"
			      "JMX (%s): %d -> %d",
			      Poco::Path(__FILE__).getBaseName().c_str(), __LINE__,
			      c_metric_forwarding_sum->get_value(), configured_limit_sum(),
			      c_prometheus_max->get_key_string().c_str(), c_prometheus_max->configured(), c_prometheus_max->get_value(),
			      c_statsd_max->get_key_string().c_str(), c_statsd_max->configured(), c_statsd_max->get_value(),
			      c_app_checks_max->get_key_string().c_str(), c_app_checks_max->configured(), c_app_checks_max->get_value(),
			      c_jmx_max->get_key_string().c_str(), c_jmx_max->configured(), c_jmx_max->get_value());
	}
	else
	{
		// These values already exist in the log, but print them out as a group
		// for supportability.
		SINSP_INFO("%s:%d: The total allowed metric limit per agent sample for this node is %d. Metric limits are configured as follows:\n"
			   "Prometheus (%s): %d\n"
			   "StatsD (%s): %d\n"
			   "AppChecks (%s): %d\n"
			   "JMX (%s): %d",
			   Poco::Path(__FILE__).getBaseName().c_str(), __LINE__,
			   c_metric_forwarding_sum->get_value(),
			   c_prometheus_max->get_key_string().c_str(), c_prometheus_max->get_value(),
			   c_statsd_max->get_key_string().c_str(), c_statsd_max->get_value(),
			   c_app_checks_max->get_key_string().c_str(), c_app_checks_max->get_value(),
			   c_jmx_max->get_key_string().c_str(), c_jmx_max->get_value());
	}

}

} // namespace metric_forwarding_configuration
