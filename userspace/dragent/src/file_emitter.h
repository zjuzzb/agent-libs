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
#include "protocol.h"
#include "analyzer_flush_message.h"

namespace dragent
{

// Base class for both metrics_file_emitter/protobuf_file_emitter. The
// base class handles the mechanics of creating the output directory
// and providing options for emitting
// flush_data_message/serialize_buffers but the subclasses call the
// right methods to actually write messages.

class file_emitter
{
public:
	file_emitter();

	void set_output_dir(const std::string &output_dir);

	std::string get_output_dir() const;

	// Alternate ways to write files. It's expected that a
	// subclass would only call one emit_xxx() method.
	//
	// Returns whether or not the file was written to the output directory.
	bool emit_text(const std::shared_ptr<flush_data_message>& data);
	bool emit_json(const std::shared_ptr<flush_data_message>& data);
	bool emit_raw(const std::shared_ptr<serialized_buffer>& data);

	// Convienence messages to generate filenames given a timestamp and/or a message type.
	static std::string generate_dam_filename(const std::string &directory, const uint64_t timestamp);
	static std::string generate_dam_filename(const std::string &directory, const uint64_t timestamp, const uint64_t message_type);

private:

	bool emit_flush_data_message(const std::shared_ptr<flush_data_message>& data, bool json);

	// Create the output directory if needed. This returns true if the
	// output directory exists or could be creeated, false
	// otherwise. If this returns false all calls to emit_XXX
	// automatically return false.
	bool create_output_directory();

	// Utility log messages called when one of the above emit_XXX are called.
	void log_flush_data_message(const std::shared_ptr<flush_data_message>& data) const;
	void log_serialized_buffer(const std::shared_ptr<serialized_buffer>& data) const;

	std::string m_output_dir;
	bool m_createdir_attempted;
};

}  // end namespace dragent
