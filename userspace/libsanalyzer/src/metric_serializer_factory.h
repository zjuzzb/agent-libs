/**
 * @file
 *
 * Interface to metric_serializer_factory.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include "internal_metrics.h"
#include <string>

class capture_stats_source;

namespace libsanalyzer
{

class metric_serializer;

namespace metric_serializer_factory
{

/**
 * Factory method for creating concrete metric_serializer%s.  Note
 * that the client is responsible for managing and eventually deleting
 * the returned pointer.
 *
 * The parameters here match the parameters for metric_serializer%'s
 * constructor.
 */
metric_serializer* build(capture_stats_source* stats_source,
                         const internal_metrics::sptr_t& internal_metrics,
                         bool emit_metrics_to_file = false,
                         bool compress_metrics = false,
                         const std::string& metrics_directory = "");

} // namespace metric_serializer_factory

} // end namespace libsanalyzer
