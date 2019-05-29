#pragma once

#include <type_config.h>

namespace metric_forwarding_configuration
{

/**
 * Print helpful information about the config.
 */
void print();

extern type_config<int>::ptr c_prometheus_max;

extern type_config<int>::ptr c_statsd_max;

extern type_config<int>::ptr c_jmx_max;

extern type_config<int>::ptr c_app_checks_max;

}
