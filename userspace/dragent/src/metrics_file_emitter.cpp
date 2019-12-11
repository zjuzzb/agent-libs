#define __STDC_FORMAT_MACROS
#include "metrics_file_emitter.h"
#include "common_logger.h"
#include <inttypes.h>
#include <google/protobuf/util/json_util.h>
#include <unistd.h>
#include <sstream>
#include "Poco/Path.h"
#include "Poco/File.h"

namespace dragent
{

metrics_file_emitter::metrics_file_emitter() : m_protobuf_file()
{
	m_protobuf_file.exceptions(std::ofstream::failbit | std::ofstream::badbit);
}

void metrics_file_emitter::emit_log(const std::shared_ptr<flush_data_message>& data) const
{
	g_logger.format(sinsp_logger::SEV_INFO,
	                "to_file ts=%" PRIu64 ", ne=%" PRIu64 ", de=%" PRIu64
	                ", c=%.2lf"
	                ", sr=%" PRIu32 ", st=%" PRIu64,
	                data->m_ts / 100000000,
	                data->m_nevts,
	                data->m_num_drop_events,
	                data->m_my_cpuload,
	                data->m_sampling_ratio,
	                data->m_n_tids_suppressed);
}

bool metrics_file_emitter::emit_metrics_to_file(const std::shared_ptr<flush_data_message>& data)
{
	if (!should_dump())
	{
		return false;
	}

	emit_log(data);

	if (!m_protobuf_file.is_open())
	{
		std::string directory = get_metrics_directory();
		const std::string dam_file = generate_dam_filename(directory, data->m_ts);

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

	return true;
}

bool metrics_file_emitter::emit_metrics_to_json_file(
    const std::shared_ptr<flush_data_message>& data) const
{
	if (!should_dump())
	{
		return false;
	}

	emit_log(data);

	std::string directory = get_metrics_directory();

	const std::string dam_file = generate_dam_filename(directory, data->m_ts) + ".json";

	std::ofstream out(dam_file.c_str());

	if (out)
	{
		std::string json_string;

		google::protobuf::util::MessageToJsonString(*data->m_metrics, &json_string);
		out << json_string;

		const std::string symbolic_link = directory + "latest.dams.json";
		unlink(symbolic_link.c_str());
		symlink(dam_file.c_str(), symbolic_link.c_str());
	}

	return true;
}

std::string metrics_file_emitter::generate_dam_filename(const std::string& directory,
                                                        const uint64_t timestamp)
{
	std::stringstream out;

	out << directory << (timestamp / 1000000000) << ".dams";

	return out.str();
}

bool metrics_file_emitter::get_emit_metrics_to_file() const
{
	std::unique_lock<std::mutex> lock(m_metrics_dir_mutex);

	return !m_metrics_dir.empty();
}

void metrics_file_emitter::set_metrics_directory(const std::string& dir)
{
	// needs to be locked so user doesn't get bogus dir before we've "sanitized" it
	std::unique_lock<std::mutex> lock(m_metrics_dir_mutex);

	m_metrics_dir = dir;

	if (!m_metrics_dir.empty())
	{
		if (m_metrics_dir[m_metrics_dir.size() - 1] != Poco::Path::separator())
		{
			m_metrics_dir += Poco::Path::separator();
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

std::string metrics_file_emitter::get_metrics_directory() const
{
	std::unique_lock<std::mutex> lock(m_metrics_dir_mutex);

	return m_metrics_dir;
}

bool metrics_file_emitter::should_dump() const
{
	return !get_metrics_directory().empty();
}
}
