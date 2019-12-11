/**
 * @file
 *
 * Interface to metrics file emitter. Anyone who wants to dump
 * protobufs to files should create an instance of this.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once
#include <string>
#include <memory>
#include <fstream>
#include "analyzer_flush_message.h"

namespace dragent
{

class metrics_file_emitter
{
public:
	metrics_file_emitter();

	/**
	 * @return whether the data was written or not
	 */
	bool emit_metrics_to_file(const std::shared_ptr<flush_data_message>& data);

	/**
	 * @return whether the data was written or not
	 */
	bool emit_metrics_to_json_file(const std::shared_ptr<flush_data_message>& data) const;

	static std::string generate_dam_filename(const std::string& directory,
	                                         const uint64_t timestamp);

	/**
	 * Returns true if this metric_serializer is configured to emit
	 * metrics to file, false otherwise.
	 */
	bool get_emit_metrics_to_file() const;

	/**
	 * Returns the path to the directory into which this metric_serializer
	 * will write metrics to file.  This method's return value is
	 * meaningful only when get_emit_metrics_to_file() returns true.
	 */
	std::string get_metrics_directory() const;

	/**
	 * set the absolute path to the metrics directory.
	 *
	 * Setting this to "" terminates logging to file.
	 * The directory will be created if it does not exist.
	 */
	void set_metrics_directory(const std::string&);

private:
	void emit_log(const std::shared_ptr<flush_data_message>& data) const;
	bool should_dump() const;

	std::ofstream m_protobuf_file;

	mutable std::mutex m_metrics_dir_mutex;
	std::string m_root_dir;
	std::string m_metrics_dir;
};

}  // end namespace dragent
