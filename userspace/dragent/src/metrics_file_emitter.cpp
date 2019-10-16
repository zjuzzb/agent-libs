#define __STDC_FORMAT_MACROS
#include "metrics_file_emitter.h"
#include "common_logger.h"
#include <inttypes.h>
#include <google/protobuf/util/json_util.h>
#include <unistd.h>
#include <sstream>

namespace dragent
{

metrics_file_emitter::metrics_file_emitter() :
	m_protobuf_file()
{
	m_protobuf_file.exceptions(std::ofstream::failbit | std::ofstream::badbit);
}

void metrics_file_emitter::emit_log(const std::shared_ptr<flush_data_message>& data) const
{
	g_logger.format(sinsp_logger::SEV_INFO,
					"to_file ts=%" PRIu64
					", ne=%" PRIu64
					", de=%" PRIu64
					", c=%.2lf"
					", sr=%" PRIu32
					", st=%" PRIu64,
					data->m_ts / 100000000,
					data->m_nevts,
					data->m_num_drop_events,
					data->m_my_cpuload,
					data->m_sampling_ratio,
					data->m_n_tids_suppressed);
}

void metrics_file_emitter::emit_metrics_to_file(const std::shared_ptr<flush_data_message>& data,
												const std::string& directory)
{
	emit_log(data);

    if(!m_protobuf_file.is_open())
    {
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
}

void metrics_file_emitter::emit_metrics_to_json_file(const std::shared_ptr<flush_data_message>& data,
													 const std::string& directory) const
{
	emit_log(data);

    const std::string dam_file = generate_dam_filename(directory, data->m_ts) + ".json";

    std::ofstream out(dam_file.c_str());

    if(out)
    {
        std::string json_string;

        google::protobuf::util::MessageToJsonString(*data->m_metrics,
                                                    &json_string);
        out << json_string;

        const std::string symbolic_link = directory +
                                          "latest.dams.json";
        unlink(symbolic_link.c_str());
        symlink(dam_file.c_str(), symbolic_link.c_str());
    }
}

std::string metrics_file_emitter::generate_dam_filename(const std::string& directory,
														const uint64_t timestamp)
{
    std::stringstream out;

    out << directory << (timestamp / 1000000000) << ".dams";

    return out.str();
}

}
