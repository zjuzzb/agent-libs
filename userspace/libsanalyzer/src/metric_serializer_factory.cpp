/**
 * @file
 *
 * Implementation of metric_serializer_factory.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "metric_serializer_factory.h"
#include "capture_stats_source.h"
#include "internal_metrics.h"
#include "metric_serializer.h"
#include "protobuf_metric_serializer.h"
#include <string>

namespace libsanalyzer
{

metric_serializer* metric_serializer_factory::build(
		capture_stats_source* const stats_source,
		const internal_metrics::sptr_t& internal_metrics,
		const sinsp_configuration* configuration)
{
	// Note: This currently returns only a pointer to a concrete
	//       protobuf_metric_serializer.  The intention here is to
	//       decouple client code from the concrete class, so that we can
	//       eventually UT the client code with a appropriate UT sub
	//       realization of this interface.
	return new protobuf_metric_serializer(stats_source,
	                                      internal_metrics,
	                                      configuration);

}

} // end namespace libsanalyzer
