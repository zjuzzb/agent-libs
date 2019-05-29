#include "metric_forwarding_configuration.h"
#include <type_config.h>

namespace
{

const unsigned LEGACY_PROM_METRICS_HARD_LIMIT = 3000;
const unsigned LEGACY_STATSD_METRIC_HARD_LIMIT = 1000;
const unsigned LEGACY_APP_METRICS_HARD_LIMIT = 3000;
const unsigned LEGACY_JMX_METRICS_HARD_LIMIT = 3000;


type_config<bool>::ptr c_feature_flag =
   type_config_builder<bool>(false /*default*/,
			     "Feature flag to turn on metric forwarding. This can be deleted once the feature is validated.",
			     "feature_flag_metric_forwarding_configuration")
	.hidden()
	.get();

type_config<int>::ptr c_metric_forwarding_sum =
   type_config_builder<int>(10000 /*default*/,
			    "The maxiumum total of all prometheus, jmx, statsd and app check metrics.",
			    "metric_forwarding_limit")
	.min(0)
	.max(15000)
	.hidden()
	.get();

/**
 * The sum of all of the metrics must be below the
 * c_metric_forwarding_sum.  If they are not, then the max values
 * are dropped proportionally.
 *
 * Returns the value which is used to change the given config to
 * the allowed config.
 */
float metric_divisor()
{
	if(0 == c_metric_forwarding_sum->get())
	{
		return 0;
	}

	float divisor = static_cast<float>(metric_forwarding_configuration::c_prometheus_max->configured() +
					   metric_forwarding_configuration::c_jmx_max->configured() +
					   metric_forwarding_configuration::c_statsd_max->configured() +
					   metric_forwarding_configuration::c_app_checks_max->configured()) /
					   static_cast<float>(c_metric_forwarding_sum->configured());

	if(divisor < 1.0)
	{
		return 1.0;
	}

	return divisor;
}

void adjust_limit(int& limit, const int legacy_hard_limit)
{
	if(!c_feature_flag->get())
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
	.max(10000)
	.post_init([](type_config<int>& config)
	{
		adjust_limit(config.get(), LEGACY_PROM_METRICS_HARD_LIMIT);
	})
	.get();

type_config<int>::ptr c_statsd_max =
   type_config_builder<int>(100 /*default*/,
			    "The maximum number of statsd metrics that will be reported to Sysdig Monitor.",
			    "statsd",
			    "limit")
	.min(0)
	.max(10000)
	.post_init([](type_config<int>& config)
	{
		adjust_limit(config.get(), LEGACY_STATSD_METRIC_HARD_LIMIT);
	})
	.get();

type_config<int>::ptr c_jmx_max =
   type_config_builder<int>(500 /*default*/,
			    "The maximum number of jmx metrics that will be reported to Sysdig Monitor.",
			    "jmx",
			    "limit")
	.min(0)
	.max(5000)
	.post_init([](type_config<int>& config)
	{
		adjust_limit(config.get(), LEGACY_JMX_METRICS_HARD_LIMIT);
	})
	.get();

type_config<int>::ptr c_app_checks_max =
   type_config_builder<int>(500 /*default*/,
			    "The maximum number of app checks metrics that will be reported to Sysdig Monitor.",
			    "app_checks_limit")
	.min(0)
	.max(5000)
	.post_init([](type_config<int>& config)
	{
		adjust_limit(config.get(), LEGACY_APP_METRICS_HARD_LIMIT);
	})
	.get();


void print()
{
	if(!c_feature_flag->get())
	{
		return;
	}

// todo bryan SMAGENT-1633
// print appropriate based on the spec

}

} // namespace metric_forwarding_configuration
