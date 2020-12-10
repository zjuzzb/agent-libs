#include "handshake_helpers.h"
#include "common_logger.h"

using namespace draiosproto;

COMMON_LOGGER();

namespace handshake_helpers
{

uint32_t metric_limit_to_uint32(draiosproto::custom_metric_limit_value value)
{
	switch (value) 
	{
	case custom_metric_limit_value::CUSTOM_METRIC_DEFAULT:
		LOG_ERROR("The custom metric limit doesn't apply when running in "
			  "default mode. This error indicates a code problem.");
		return 10000;
	case custom_metric_limit_value::CUSTOM_METRIC_10k:
		return 10000;
	case custom_metric_limit_value::CUSTOM_METRIC_20k:
		return 20000;
	case custom_metric_limit_value::CUSTOM_METRIC_50k:
		return 50000;
	case custom_metric_limit_value::CUSTOM_METRIC_100k:
		return 100000;
	}

	LOG_ERROR("Invalid custom metric limit value This error indicates a code problem.");
	return 10000;
}

}
