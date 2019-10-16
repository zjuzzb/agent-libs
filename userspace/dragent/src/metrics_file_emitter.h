/**
 * @file
 *
 * Interface to metrics file emitter. Anyone who wants to dump
 * protobufs to files should create an instance of this.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once
#include  <string>
#include <memory>
#include <fstream>
#include "analyzer_flush_message.h"

namespace dragent
{
class metrics_file_emitter
{
public:
	metrics_file_emitter();

	void emit_metrics_to_file(const std::shared_ptr<flush_data_message>& data,
							  const std::string& directory);
	void emit_metrics_to_json_file(const std::shared_ptr<flush_data_message>& data,
								   const std::string& directory) const;
	static std::string generate_dam_filename(const std::string& directory, const uint64_t timestamp);
private:
	void emit_log(const std::shared_ptr<flush_data_message>& data) const;

	std::ofstream m_protobuf_file;
};

} // end namespace dragent
