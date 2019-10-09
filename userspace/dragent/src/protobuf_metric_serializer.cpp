/**
 * @file
 *
 * Implementation of protobuf_metric_serializer, a concrete
 * metric_serializer that serializes the analyzer to protobuf.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#define __STDC_FORMAT_MACROS
#include "protobuf_metric_serializer.h"
#include "analyzer_flush_message.h"
#include "dragent_message_queues.h"
#include "config.h"
#include "metric_store.h"
#include "tracer_emitter.h"
#include "type_config.h"
#include <chrono>
#include <google/protobuf/util/json_util.h>
#include <sstream>
#include <inttypes.h>

namespace
{

type_config<bool> s_emit_protobuf_json(
		false,
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
	                       const sinsp_logger::severity severity = sinsp_logger::SEV_INFO):
		m_start_time(std::chrono::steady_clock::now()),
		m_label(label),
		m_severity(severity)
	{ }

	~scoped_duration_logger()
	{
		const auto now = std::chrono::steady_clock::now();
		const auto duration_ms =
		        std::chrono::duration_cast<std::chrono::milliseconds>(
		                        now - m_start_time).count();
		g_logger.format(m_severity,
		                "%s: duration: %zu ms",
		                m_label.c_str(),
		                static_cast<size_t>(duration_ms));
	}

private:
	const std::chrono::time_point<std::chrono::steady_clock> m_start_time;
	const std::string m_label;
	const sinsp_logger::severity m_severity;
};

} // end namespace

namespace dragent
{

protobuf_metric_serializer::protobuf_metric_serializer(
        std::shared_ptr<const capture_stats_source> stats_source,
        const std::string& root_dir,
        uncompressed_sample_handler& sample_handler,
        flush_queue* input_queue,
        protocol_queue* output_queue) :
    metric_serializer(root_dir, sample_handler, input_queue, output_queue),
    dragent::watchdog_runnable("serializer"),
	m_stop_thread(false),
	m_capture_stats_source(stats_source),
	m_protobuf_file(),
	m_prev_sample_evtnum(0),
	m_prev_sample_time(0),
    m_prev_sample_num_drop_events(0),
    m_serialized_events(0)
{
	m_protobuf_file.exceptions(std::ofstream::failbit | std::ofstream::badbit);
}

protobuf_metric_serializer::~protobuf_metric_serializer()
{
	stop();

	// we effectively own this, so clear it on destruction
	libsanalyzer::metric_store::store(nullptr);
}

void protobuf_metric_serializer::do_run()
{
	while(!m_stop_thread && heartbeat())
	{
		try
		{
			data flush_data;
			bool ret = m_input_queue->get(&flush_data, DEFAULT_MQUEUE_READ_TIMEOUT_MS);
			if (!ret)
			{
				continue;
			}

			if(m_stop_thread)
			{
				return;
			}

			(void)heartbeat();
			do_serialization(flush_data);
		}
		catch(const std::ifstream::failure& ex)
		{
			g_logger.format(sinsp_logger::SEV_ERROR,
			                "ifstream::failure during serialization: %s",
			                ex.what());
		}
		catch(const sinsp_exception& ex)
		{
			g_logger.format(sinsp_logger::SEV_ERROR,
			                "sinsp_exception during serialization: %s",
			                ex.what());
		}
	}
}

void protobuf_metric_serializer::do_serialization(data& data)
{

	scoped_duration_logger scoped_log("protobuf serialization",
	                                  sinsp_logger::SEV_DEBUG);
	uint64_t nevts = 0;
	uint64_t num_drop_events = 0;

	if(data->m_evt_num != metric_serializer::NO_EVENT_NUMBER)
	{
		nevts = data->m_evt_num - m_prev_sample_evtnum;
		m_prev_sample_evtnum = data->m_evt_num;
		m_prev_sample_time = data->m_ts;
	}

	// Get the number of dropped events and include that in the log message
	scap_stats st = {};
	m_capture_stats_source->get_capture_stats(&st);

	num_drop_events = st.n_drops - m_prev_sample_num_drop_events;
	m_prev_sample_num_drop_events = st.n_drops;

	libsanalyzer::metric_store::store(data->m_metrics);
	data->m_metrics_sent.exchange(true);
	std::shared_ptr<serialized_buffer> q_item =
	    m_uncompressed_sample_handler.handle_uncompressed_sample(data->m_ts,
	                                                             data->m_metrics);

	if (!m_output_queue->put(q_item, protocol_queue::BQ_PRIORITY_MEDIUM))
	{
		g_logger.format(sinsp_logger::SEV_WARNING, "Queue full, discarding sample");
	}

	if(get_emit_metrics_to_file())
	{
		g_logger.format(sinsp_logger::SEV_INFO,
		                "to_file ts=%" PRIu64
		                ", ne=%" PRIu64
		                ", de=%" PRIu64
		                ", c=%.2lf"
		                ", sr=%" PRIu32
		                ", st=%" PRIu64,
		                data->m_ts / 100000000,
		                nevts,
		                num_drop_events,
		                data->m_my_cpuload,
		                data->m_sampling_ratio,
		                st.n_tids_suppressed);

		if(s_emit_protobuf_json.get_value())
		{
			emit_metrics_to_json_file(data);
		}
		else
		{
			emit_metrics_to_file(data);
		}
	}

	++m_serialized_events;
}

// This function is pretty vestigial
void protobuf_metric_serializer::serialize(data&& data)
{
	m_input_queue->put(data);
}

void protobuf_metric_serializer::drain() const
{
	while(m_input_queue->size() > 0 && !m_stop_thread)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
}

void protobuf_metric_serializer::stop()
{
	m_stop_thread = true;
	m_input_queue->clear();
}

void protobuf_metric_serializer::emit_metrics_to_file(const data& data)
{
	if(!m_protobuf_file.is_open())
	{
		const std::string dam_file = generate_dam_filename(
				get_metrics_directory(),
		        data->m_ts);

		m_protobuf_file.open(dam_file);
	}

	//
	// The agent is writing individual metrics protobufs, but we want the
	// contents of the file to be readable as a metrics_list protobuf. So
	// add a "metrics {" header and "}" trailer to each protobuf so it
	// appears to be a metrics_list item (i.e., message).
	//
	const std::string header = "metrics {\n";
	const std::string pbstr = data->m_metrics->DebugString();
	const std::string footer = "}\n";

	m_protobuf_file << header << pbstr << footer << std::flush;
	m_protobuf_file.flush();
}

void protobuf_metric_serializer::emit_metrics_to_json_file(const data& data) const
{
	//
	// Don't generate a zero-named file
	if(data->m_evt_num == metric_serializer::NO_EVENT_NUMBER)
	{
		return;
	}

	const std::string dam_file = generate_dam_filename(
			get_metrics_directory(),
	        data->m_ts) + ".json";

	std::ofstream out(dam_file.c_str());

	if(out)
	{
		std::string json_string;

		google::protobuf::util::MessageToJsonString(*data->m_metrics,
		                                            &json_string);
		out << json_string;

		const std::string symbolic_link = get_metrics_directory() +
		                                  "latest.dams.json";
		unlink(symbolic_link.c_str());
		symlink(dam_file.c_str(), symbolic_link.c_str());
	}
}

uint64_t protobuf_metric_serializer::get_prev_sample_evtnum() const
{
	return m_prev_sample_evtnum;
}

uint64_t protobuf_metric_serializer::get_prev_sample_time() const
{
	return m_prev_sample_time;
}

uint64_t protobuf_metric_serializer::get_prev_sample_num_drop_events() const
{
	return m_prev_sample_num_drop_events;
}

uint64_t protobuf_metric_serializer::get_num_serialized_events() const
{
	return m_serialized_events;
}

std::string protobuf_metric_serializer::generate_dam_filename(
		const std::string& directory,
		const uint64_t timestamp)
{
	std::stringstream out;

	out << directory << (timestamp / 1000000000) << ".dams";

	return out.str();
}

} // end namespace dragent
