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
#include "Poco/File.h"
#include "Poco/Path.h"
#include "analyzer_flush_message.h"

namespace dragent
{

type_config<std::string> metric_serializer::c_metrics_dir(
	"",
	"metricsfile.location. If unset, metrics won't be saved to disk.",
	"metricsfile",
	"location");

metric_serializer::metric_serializer(const std::string& root_dir,
                                     uncompressed_sample_handler& sample_handler,
                                     flush_queue* input_queue,
                                     protocol_queue* output_queue):
	m_metrics_dir_mutex(),
	m_root_dir(root_dir),
	m_metrics_dir(""),
    m_uncompressed_sample_handler(sample_handler),
    m_input_queue(input_queue),
    m_output_queue(output_queue)
{ 
	if (!c_metrics_dir.get_value().empty())
	{
		std::string dir = Poco::Path(m_root_dir).append(c_metrics_dir.get_value()).toString();

		set_metrics_directory(dir);
	}
}

bool metric_serializer::get_emit_metrics_to_file() const
{
	std::unique_lock<std::mutex> lock(m_metrics_dir_mutex);

	return !m_metrics_dir.empty();
}

void metric_serializer::set_metrics_directory(const std::string& dir)
{
	// needs to be locked so user doesn't get bogus dir before we've "sanitized" it
	std::unique_lock<std::mutex> lock(m_metrics_dir_mutex);

	m_metrics_dir = dir;

	if (!m_metrics_dir.empty())
	{
		if (m_metrics_dir[m_metrics_dir.size() -1] != DIR_PATH_SEPARATOR)
		{
			m_metrics_dir += DIR_PATH_SEPARATOR;
		}

		Poco::File md(m_metrics_dir);
		md.createDirectories();
	}
	else
	{
		g_logger.format(sinsp_logger::SEV_INFO,
				"metricsfile.location not specified, metrics won't be saved to disk.");
	}
}

std::string metric_serializer::get_metrics_directory() const
{
	std::unique_lock<std::mutex> lock(m_metrics_dir_mutex);

	return m_metrics_dir;
}

} // end namespace dragent
