/**
 * @file
 *
 * Interface to protobuf file emitter. Anyone who wants to dump
 * protobufs to files should create an instance of this.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once
#include <string>
#include <vector>
#include <memory>
#include <set>

#include "protocol.h"
#include "type_config.h"
#include "file_emitter.h"

namespace dragent
{

class protobuf_file_emitter : public file_emitter
{
public:
	static type_config<std::string> c_messages_dir;
	static type_config<std::vector<std::string>> c_message_types;

	protobuf_file_emitter(const std::string &root_dir);

	bool emit(const std::shared_ptr<serialized_buffer> & data);

private:
	bool should_dump(const std::shared_ptr<serialized_buffer>& data) const;

	std::set<int> m_message_type_nums;
};

}  // end namespace dragent
