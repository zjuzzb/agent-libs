/**
 * @file
 *
 * Implementation of metric_serializer -- an abstract base class for analyzer
 * metric serialization.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "metric_serializer.h"
#include "config.h"
#include "sinsp.h"
#include "analyzer_flush_message.h"

namespace dragent
{

type_config<std::string> metric_serializer::c_metrics_dir(
    "",
    "Location where serialized metrics are written to file, if set.",
    "metricsfile",
    "location");

metric_serializer::metric_serializer(const std::string& root_dir,
                                     uncompressed_sample_handler& sample_handler,
                                     flush_queue* input_queue,
                                     protocol_queue* output_queue):
    m_uncompressed_sample_handler(sample_handler),
    m_input_queue(input_queue),
    m_output_queue(output_queue)
{
}

} // end namespace dragent
