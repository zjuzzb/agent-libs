/**
 * @file
 *
 * Implementation of protobuf_metric_serializer, a concrete
 * metric_serializer that serializes the analyzer to protobuf.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "protobuf_metric_serializer.h"
#include "analyzer_flush_message.h"
#include "dragent_message_queues.h"
#include "config.h"
#include "metric_store.h"
#include "tracer_emitter.h"
#include "type_config.h"
#include "Poco/Path.h"
#include "Poco/File.h"
#include <chrono>
#include "protocol.h"

namespace
{

type_config<bool> s_emit_protobuf_json(false,
                                       "If true, emit each protobuf as a separate JSON file",
                                       "metricsfile",
                                       "json");

/**
 * Generate a log on destruction that includes the object's lifetime in
 * milliseconds.
 */
class scoped_duration_logger
{
public:
	scoped_duration_logger(const std::string label,
	                       const sinsp_logger::severity severity = sinsp_logger::SEV_INFO)
	    : m_start_time(std::chrono::steady_clock::now()), m_label(label), m_severity(severity)
	{
	}

	~scoped_duration_logger()
	{
		const auto now = std::chrono::steady_clock::now();
		const auto duration_ms =
		    std::chrono::duration_cast<std::chrono::milliseconds>(now - m_start_time).count();
		g_logger.format(
		    m_severity, "%s: duration: %zu ms", m_label.c_str(), static_cast<size_t>(duration_ms));
	}

private:
	const std::chrono::time_point<std::chrono::steady_clock> m_start_time;
	const std::string m_label;
	const sinsp_logger::severity m_severity;
};

}  // end namespace

namespace dragent
{

protobuf_metric_serializer::protobuf_metric_serializer(std::shared_ptr<const capture_stats_source> stats_source,
    const std::string& root_dir,
    uncompressed_sample_handler& sample_handler,
    flush_queue* input_queue,
    protocol_queue* output_queue,
    std::shared_ptr<protobuf_compressor>& compressor)
    : metric_serializer(root_dir, sample_handler, input_queue, output_queue),
      dragent::watchdog_runnable("serializer"),
      m_stop_thread(false),
      m_capture_stats_source(stats_source),
      m_serializations_completed(0),
      m_file_emitter(),
      m_compressor(compressor),
      m_compression_source(nullptr)
{
	if (!c_metrics_dir.get_value().empty())
	{
		std::string dir = Poco::Path(root_dir).append(c_metrics_dir.get_value()).toString();
		set_metrics_directory(dir);
	}
}

protobuf_metric_serializer::protobuf_metric_serializer(std::shared_ptr<const capture_stats_source> stats_source,
                           const std::string& root_dir,
                           uncompressed_sample_handler& sample_handler,
                           flush_queue* input_queue,
                           protocol_queue* output_queue,
                           compression_method_source* source)
    : metric_serializer(root_dir, sample_handler, input_queue, output_queue),
      dragent::watchdog_runnable("serializer"),
      m_stop_thread(false),
      m_capture_stats_source(stats_source),
      m_serializations_completed(0),
      m_file_emitter(),
      m_compressor(nullptr),
      m_compression_source(source)
{
	if (!source)
	{
		g_logger.format(sinsp_logger::SEV_WARNING,
		                "Created a serializer with a null compression source");
	}
	if (!c_metrics_dir.get_value().empty())
	{
		std::string dir = Poco::Path(root_dir).append(c_metrics_dir.get_value()).toString();
		set_metrics_directory(dir);
	}
}

protobuf_metric_serializer::~protobuf_metric_serializer()
{
	stop();

	// we effectively own this, so clear it on destruction
	libsanalyzer::metric_store::store(nullptr);
}

void protobuf_metric_serializer::do_run()
{
	while (!m_stop_thread && heartbeat())
	{
		try
		{
			flush_data data;
			bool ret = m_input_queue->get(&data, DEFAULT_MQUEUE_READ_TIMEOUT_MS);
			if (!ret)
			{
				continue;
			}

			if (m_stop_thread)
			{
				return;
			}

			(void)heartbeat();
			do_serialization(data);
		}
		catch (const std::ifstream::failure& ex)
		{
			g_logger.format(
			    sinsp_logger::SEV_ERROR, "ifstream::failure during serialization: %s", ex.what());
		}
		catch (const sinsp_exception& ex)
		{
			g_logger.format(
			    sinsp_logger::SEV_ERROR, "sinsp_exception during serialization: %s", ex.what());
		}
	}
}

void protobuf_metric_serializer::do_serialization(flush_data& data)
{

	scoped_duration_logger scoped_log("protobuf serialization", sinsp_logger::SEV_DEBUG);

	std::shared_ptr<protobuf_compressor> compressor = m_compressor;
	if (m_compression_source)
	{
		// If we have a registered source of truth, it will override
		// a stored compressor
		compressor = m_compression_source->get_negotiated_compression_method();
	}

	if (!compressor)
	{
		// A null compressor. In order to avoid a situation where we can't
		// serialize any protobufs at all, we will fall back to sending
		// uncompressed data
		compressor = null_protobuf_compressor::get();
	}

	libsanalyzer::metric_store::store(data->m_metrics);
	data->m_metrics_sent->exchange(true);
	std::shared_ptr<serialized_buffer> q_item =
	    m_uncompressed_sample_handler.handle_uncompressed_sample(
	        data->m_ts,
	        data->m_metrics,
	        data->m_flush_interval,
	        compressor);

	if (!m_output_queue->put(q_item, protocol_queue::BQ_PRIORITY_MEDIUM))
	{
		g_logger.format(sinsp_logger::SEV_WARNING, "Queue full, discarding sample");
	}

	if (s_emit_protobuf_json.get_value())
	{
		m_file_emitter.emit_metrics_to_json_file(data);
	}
	else
	{
		m_file_emitter.emit_metrics_to_file(data);
	}

	++m_serializations_completed;
}

// This function is pretty vestigial
void protobuf_metric_serializer::serialize(flush_data&& data)
{
	m_input_queue->put(data);
}

void protobuf_metric_serializer::drain() const
{
	while (m_input_queue->size() > 0 && !m_stop_thread)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
}

void protobuf_metric_serializer::stop()
{
	m_stop_thread = true;
	m_input_queue->clear();
}

uint64_t protobuf_metric_serializer::get_num_serializations_completed() const
{
	return m_serializations_completed;
}

bool protobuf_metric_serializer::get_emit_metrics_to_file() const
{
	return m_file_emitter.get_emit_metrics_to_file();
}

std::string protobuf_metric_serializer::get_metrics_directory() const
{
	return m_file_emitter.get_metrics_directory();
}

void protobuf_metric_serializer::set_metrics_directory(const std::string& dir)
{
	m_file_emitter.set_metrics_directory(dir);
}

bool protobuf_metric_serializer::set_compression(std::shared_ptr<protobuf_compressor> compressor)
{
	if (!compressor)
	{
		return false;
	}
	m_compressor = compressor;
	return true;
}

void protobuf_metric_serializer::set_compression_source(compression_method_source* source)
{
	m_compression_source = source;
}

}  // end namespace dragent
