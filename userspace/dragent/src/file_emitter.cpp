#define __STDC_FORMAT_MACROS
#include "common_logger.h"
#include "draios.pb.h"
#include "file_emitter.h"
#include "utils.h"

#include "Poco/File.h"
#include "Poco/Path.h"

#include <google/protobuf/util/json_util.h>

#include <fstream>
#include <inttypes.h>
#include <sstream>
#include <unistd.h>

namespace
{
COMMON_LOGGER();
}

namespace dragent
{
file_emitter::file_emitter() : m_createdir_attempted(false) {}

void file_emitter::set_output_dir(const std::string& output_dir)
{
	m_createdir_attempted = false;

	m_output_dir = output_dir;

	// Add a trailing '/' to output dir if necessary
	if (output_dir != "" && m_output_dir.back() != '/')
	{
		m_output_dir += '/';
	}
}

std::string file_emitter::get_output_dir() const
{
	return m_output_dir;
}

bool file_emitter::emit_text(const std::shared_ptr<flush_data_message>& data)
{
	return emit_flush_data_message(data, false);
}

bool file_emitter::emit_json(const std::shared_ptr<flush_data_message>& data)
{
	return emit_flush_data_message(data, true);
}

bool file_emitter::emit_raw(const std::shared_ptr<serialized_buffer>& data)
{
	if (!create_output_directory())
	{
		return false;
	}

	log_serialized_buffer(data);

	std::string filename = generate_dam_filename(m_output_dir, data->ts_ns, data->message_type);
	std::ofstream ofile(filename);

	if (!ofile)
	{
		LOG_ERROR("Could not open output file %s (%s)", filename.c_str(), strerror(errno));
		return false;
	}

	LOG_DEBUG("writing serialized buffer to output file %s", filename.c_str());

	ofile << data->buffer << std::flush;
	ofile.close();

	if (!ofile)
	{
		LOG_ERROR("Could not write to output file %s (%s)", filename.c_str(), strerror(errno));
		return false;
	}

	return true;
}

std::string file_emitter::generate_dam_filename(const std::string& directory,
                                                const uint64_t timestamp)
{
	std::stringstream out;

	out << directory << (timestamp / 1000000000) << ".dams";

	return out.str();
}

std::string file_emitter::generate_dam_filename(const std::string& directory,
                                                const uint64_t timestamp,
                                                const uint64_t message_type)
{
	std::stringstream out;

	out << directory << (timestamp / 1000000000) << "-" << std::to_string(message_type) << ".dams";

	return out.str();
}

bool file_emitter::emit_message(const google::protobuf::Message& msg)
{
	if (!create_output_directory())
	{
		return false;
	}

	auto ts = sinsp_utils::get_current_time_ns();

	std::string filename = generate_dam_filename(m_output_dir, ts, 132);

	std::ofstream ofile(filename);

	if (!ofile)
	{
		LOG_ERROR("Could not open output file %s (%s)", filename.c_str(), strerror(errno));
		return false;
	}

	LOG_DEBUG("writing message to output file %s", filename.c_str());

	const std::string pbstr = msg.DebugString();

	ofile << pbstr << std::flush;
	ofile.close();

	if (!ofile)
	{
		LOG_ERROR("Could not write to output file %s (%s)", filename.c_str(), strerror(errno));
		return false;
	}

	return true;
}

bool file_emitter::emit_flush_data_message(const std::shared_ptr<flush_data_message>& data,
                                           bool json)
{
	if (!create_output_directory())
	{
		return false;
	}

	log_flush_data_message(data);

	std::string filename = generate_dam_filename(m_output_dir, data->m_ts);

	if (json)
	{
		filename += ".json";
	}

	std::ofstream ofile(filename);

	if (!ofile)
	{
		LOG_ERROR("Could not open output file %s (%s)", filename.c_str(), strerror(errno));
		return false;
	}

	//
	// The agent is writing individual metrics protobufs, but we want the
	// contents of the file to be readable as a metrics_list protobuf. So
	// add a "metrics {" header and "}" trailer to each protobuf so it
	// appears to be a metrics_list item (i.e., message).
	//

	LOG_DEBUG("writing%s flush data message to output file %s",
	          (json ? " json" : " "),
	          filename.c_str());

	if (json)
	{
		std::string json_string;

		google::protobuf::util::MessageToJsonString(*data->m_metrics, &json_string);
		ofile << json_string << std::flush;
		ofile.close();

		// Only change the symlink if the write
		// succeeded. Error return/log happens later.
		if (ofile)
		{
			const std::string symbolic_link = m_output_dir + "latest.dams.json";
			Poco::File sf(symbolic_link);

			if (sf.exists())
			{
				if (unlink(symbolic_link.c_str()) != 0)
				{
					LOG_ERROR("Could not remove symlink to %s (%s)",
					          symbolic_link.c_str(),
					          strerror(errno));
					return false;
				}
			}

			if (symlink(filename.c_str(), symbolic_link.c_str()) != 0)
			{
				LOG_ERROR("Could not set symlink from %s to %s (%s)",
				          filename.c_str(),
				          symbolic_link.c_str(),
				          strerror(errno));
				return false;
			}
		}
	}
	else
	{
		const std::string header = "metrics {\n";
		const std::string pbstr = data->m_metrics->DebugString();
		const std::string footer = "}\n";

		ofile << header << pbstr << footer << std::flush;
		ofile.close();
	}

	if (!ofile)
	{
		LOG_ERROR("Could not write to output file %s (%s)", filename.c_str(), strerror(errno));
		return false;
	}

	return true;
}

bool file_emitter::create_output_directory()
{
	if (m_createdir_attempted)
	{
		return (m_output_dir != "");
	}

	m_createdir_attempted = true;

	if (m_output_dir == "")
	{
		LOG_DEBUG("Empty output directory, skipping");
		return false;
	}

	LOG_DEBUG("Creating file output directory %s", m_output_dir.c_str());

	try
	{
		Poco::File md(m_output_dir);
		md.createDirectories();
	}
	catch (Poco::Exception& e)
	{
		LOG_ERROR(
		    "Could not create file output directory %s (%s). Later attempts to write "
		    "files will fail",
		    m_output_dir.c_str(),
		    e.what());
		m_output_dir = "";
		return false;
	}

	return true;
}

void file_emitter::log_flush_data_message(const std::shared_ptr<flush_data_message>& data) const
{
	LOG_INFO("to_file ts=%" PRIu64 ", ne=%" PRIu64 ", de=%" PRIu64
	         ", c=%.2lf"
	         ", sr=%" PRIu32 ", st=%" PRIu64,
	         data->m_ts / 100000000,
	         data->m_nevts,
	         data->m_num_drop_events,
	         data->m_my_cpuload,
	         data->m_sampling_ratio,
	         data->m_n_tids_suppressed);
}

void file_emitter::log_serialized_buffer(const std::shared_ptr<serialized_buffer>& data) const
{
	LOG_INFO("to_file ts=%" PRIu64 " msgtype=%" PRIu32,
	         data->ts_ns / 100000000,
	         data->message_type);
}

}  // namespace dragent
