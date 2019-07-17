/**
 * @file
 *
 * Implementation of protobuf_metric_serializer, a concrete
 * metric_serializer that serializes the analyzer to protobuf.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "protobuf_metric_serializer.h"
#include "analyzer_callback_interface.h"
#include "config.h"
#include "metric_store.h"
#include "tracer_emitter.h"
#include "type_config.h"
#include <chrono>
#include <google/protobuf/util/json_util.h>
#include <sstream>

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

namespace libsanalyzer
{

protobuf_metric_serializer::protobuf_metric_serializer(
		capture_stats_source* const stats_source,
		const internal_metrics::sptr_t& internal_metrics,
		const std::string& root_dir) :
	metric_serializer(internal_metrics, root_dir),
	m_data(),
	m_data_mutex(),
	m_data_available_condition(),
	m_serialization_complete_condition(),
	m_stop_thread(false),
	m_capture_stats_source(stats_source),
	m_protobuf_file(),
	m_prev_sample_evtnum(0),
	m_prev_sample_time(0),
	m_prev_sample_num_drop_events(0),
	m_thread(&protobuf_metric_serializer::serialization_thread, this)
{
	m_protobuf_file.exceptions(std::ofstream::failbit | std::ofstream::badbit);
}

protobuf_metric_serializer::~protobuf_metric_serializer()
{
	m_stop_thread = true;

	// Wait for the async thread to finish whatever it's working on
	// if it's working on anything; it will drop m_data_mutex.
	{
		std::unique_lock<std::mutex> lock(m_data_mutex);

		// If there's no data (which should usually be the case
		// here), then the async thread is waiting for work.  Wake
		// it up so that it can notice m_stop_thread is set.  It
		// will then terminate itself.
		if(m_data.get() == nullptr)
		{
			m_data_available_condition.notify_one();
		}
	}

	// Wait for it to actually die
	m_thread.join();
}

void protobuf_metric_serializer::serialization_thread()
{
	while(!m_stop_thread)
	{
		try
		{
			do_serialization();
		}
		catch(const std::ifstream::failure& ex)
		{
			g_logger.format(sinsp_logger::SEV_ERROR,
			                "ifstream::failure during serialization: %s",
					ex.what());
			std::unique_lock<std::mutex> lock(m_data_mutex);
			clear_data();
		}
		catch(const sinsp_exception& ex)
		{
			g_logger.format(sinsp_logger::SEV_ERROR,
			                "sinsp_exception during serialization: %s",
					ex.what());
			std::unique_lock<std::mutex> lock(m_data_mutex);
			clear_data();
		}
	}
}

void protobuf_metric_serializer::do_serialization()
{
	tracer_emitter ser_trc("serialize");
	std::unique_lock<std::mutex> lock(m_data_mutex);

	// Wait for work to do
	while(!m_stop_thread && (m_data.get() == nullptr))
	{
		m_data_available_condition.wait(lock);
	}

	if(m_stop_thread)
	{
		return;
	}

	scoped_duration_logger scoped_log("protobuf serialization",
	                                  sinsp_logger::SEV_DEBUG);
	uint64_t nevts = 0;
	uint64_t num_drop_events = 0;

	if(m_data->m_evt_num != metric_serializer::NO_EVENT_NUMBER)
	{
		nevts = m_data->m_evt_num - m_prev_sample_evtnum;
		m_prev_sample_evtnum = m_data->m_evt_num;


		// Subsampling can cause repeated samples, which we skip here
		if(m_prev_sample_time != 0)
		{
			if(m_data->m_ts == m_prev_sample_time)
			{
				clear_data();
				return;
			}
		}

		m_prev_sample_time = m_data->m_ts;
	}

	// Get the number of dropped events and include that in the log message
	scap_stats st = {};
	m_capture_stats_source->get_capture_stats(&st);

	num_drop_events = st.n_drops - m_prev_sample_num_drop_events;
	m_prev_sample_num_drop_events = st.n_drops;

	if(get_sample_callback() != nullptr)
	{
		invoke_callback(st, nevts, num_drop_events);
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
				m_data->m_ts / 100000000,
				nevts,
				num_drop_events,
				m_data->m_my_cpuload,
				m_data->m_sampling_ratio,
				st.n_tids_suppressed);

		if(s_emit_protobuf_json.get())
		{
			emit_metrics_to_json_file();
		}
		else
		{
			emit_metrics_to_file();
		}
	}

	clear_data();
}

void protobuf_metric_serializer::serialize(std::unique_ptr<data>&& data)
{
	std::unique_lock<std::mutex> lock(m_data_mutex);

	// Block waiting for the async thread to finish if it's still
	// serializing the last chunk of data.  This should happen only if it
	// took more than the metric collection period (hopefully never).
	while(m_data.get() != nullptr)
	{
		m_serialization_complete_condition.wait(lock);
	}

	m_data = std::move(data);
	m_data_available_condition.notify_one();
}

void protobuf_metric_serializer::drain() const
{
	//
	// serialize() sets m_data if is empty and kicks the async thread.
	// In the async thread, do_serialization() holds m_data_mutex for the
	// duration of its execution, and when it returns is resets m_data to
	// nullptr.   As a result, if the async processing is ongoing,
	// this acquiring the lock should block until it is done.  If the
	// async processing is not in progress, this should return immediately
	// since m_data is nullptr.  We'll loop on that just in case, but
	// that's not expected to actually happen.
	//
	const data* d = nullptr;

	do
	{
		std::unique_lock<std::mutex> lock(m_data_mutex);
		d = m_data.get();
	}
	while(d != nullptr);
}

void protobuf_metric_serializer::invoke_callback(const scap_stats& st,
                                                 const uint64_t nevts,
                                                 const uint64_t num_drop_events)
{
	if(get_internal_metrics().get() != nullptr)
	{
		get_internal_metrics()->set_n_evts(st.n_evts);
		get_internal_metrics()->set_n_drops(st.n_drops);
		get_internal_metrics()->set_n_drops_buffer(st.n_drops_buffer);
		get_internal_metrics()->set_n_preemptions(st.n_preemptions);

		get_internal_metrics()->set_fp(
				static_cast<int64_t>(round(
						m_data->m_prev_flush_cpu_pct * 100)));
		get_internal_metrics()->set_sr(m_data->m_sampling_ratio);
		get_internal_metrics()->set_fl(m_data->m_prev_flushes_duration_ns / 1000000);

		bool sent;
		if(m_data->m_extra_internal_metrics)
		{
			sent = get_internal_metrics()->send_all(
					m_data->m_metrics->mutable_protos()->mutable_statsd());
		}
		else
		{
			sent = get_internal_metrics()->send_some(
					m_data->m_metrics->mutable_protos()->mutable_statsd());
		}

		if(sent)
		{
			if(g_logger.get_severity() >= sinsp_logger::SEV_TRACE)
			{
				g_logger.log(m_data->m_metrics->protos().statsd().DebugString(),
					     sinsp_logger::SEV_TRACE);
			}
		}
		else
		{
			g_logger.log("Error processing agent internal metrics.",
				     sinsp_logger::SEV_WARNING);
		}
	}
	metric_store::store(m_data->m_metrics);
	m_data->m_metrics_sent.exchange(true);
	get_sample_callback()->sinsp_analyzer_data_ready(m_data->m_ts,
							 nevts,
							 num_drop_events,
							 m_data->m_metrics.get(),
							 m_data->m_sampling_ratio,
							 m_data->m_my_cpuload,
							 m_data->m_prev_flush_cpu_pct,
							 m_data->m_prev_flushes_duration_ns,
							 st.n_tids_suppressed);
}

void protobuf_metric_serializer::emit_metrics_to_file()
{
	if(!m_protobuf_file.is_open())
	{
		const std::string dam_file = generate_dam_filename(
				get_metrics_directory(),
				m_data->m_ts);

		m_protobuf_file.open(dam_file);
	}

	//
	// The agent is writing individual metrics protobufs, but we want the
	// contents of the file to be readable as a metrics_list protobuf. So
	// add a "metrics {" header and "}" trailer to each protobuf so it
	// appears to be a metrics_list item (i.e., message).
	//
	const std::string header = "metrics {\n";
	const std::string pbstr = m_data->m_metrics->DebugString();
	const std::string footer = "}\n";

	m_protobuf_file << header << pbstr << footer << std::flush;
}

void protobuf_metric_serializer::emit_metrics_to_json_file() const
{
	// Don't generate a zero-named file
	if(m_data->m_evt_num == metric_serializer::NO_EVENT_NUMBER)
	{
		return;
	}

	const std::string dam_file = generate_dam_filename(
			get_metrics_directory(),
			m_data->m_ts) + ".json";

	std::ofstream out(dam_file.c_str());

	if(out)
	{
		std::string json_string;

		google::protobuf::util::MessageToJsonString(*m_data->m_metrics,
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

bool protobuf_metric_serializer::serialization_complete() const
{
	//
	// This will block the caller while the synchronization is in progress.
	// That's OK because this method isn't part of the interface that
	// real client code will use -- it's here to provide visibility to
	// unit tests.
	//
	std::unique_lock<std::mutex> lock(m_data_mutex);

	return m_data.get() == nullptr;
}

void protobuf_metric_serializer::clear_data()
{
	m_data.reset();
	m_serialization_complete_condition.notify_one();
}

std::string protobuf_metric_serializer::generate_dam_filename(
		const std::string& directory,
		const uint64_t timestamp)
{
	std::stringstream out;

	out << directory << (timestamp / 1000000000) << ".dams";

	return out.str();
}

} // end namespace libsanalyzer
