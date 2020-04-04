#define __STDC_FORMAT_MACROS
#include "common_logger.h"
#include "draios.pb.h"
#include "protobuf_file_emitter.h"

#include "Poco/File.h"
#include "Poco/Path.h"

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
type_config<std::string> protobuf_file_emitter::c_messages_dir(
    "",
    "Location where serialized messages are written to file, if set.",
    "serialize_messages",
    "location");

type_config<std::vector<std::string>> protobuf_file_emitter::c_message_types(
    {},
    "If set, only these message types are written to serialize_messages->location. The values "
    "should exactly match keys of the message_type enum in draios.proto",
    "serialize_messages",
    "message_types");

protobuf_file_emitter::protobuf_file_emitter(const std::string& root_dir)
{
	std::string msg;

	if (c_message_types.get_value().size() > 0)
	{
		const google::protobuf::EnumDescriptor* descriptor = draiosproto::message_type_descriptor();

		msg = "Will save protobufs for message types:";
		for (auto& mtype : c_message_types.get_value())
		{
			auto edesc = descriptor->FindValueByName(mtype);
			if (edesc == NULL)
			{
				LOG_WARNING("No message type known for %s, skipping", mtype.c_str());
			}
			else
			{
				int mtype_num = edesc->number();
				m_message_type_nums.insert(mtype_num);

				msg += " " + mtype + ":" + std::to_string(mtype_num);
			}
		}
	}
	else
	{
		msg = "Will save protobufs for all message types";
	}

	LOG_INFO(msg.c_str());

	std::string output_dir;

	if (!c_messages_dir.get_value().empty())
	{
		//  If the output directory starts with '/', just use it.
		if (c_messages_dir.get_value().at(0) == '/')
		{
			output_dir = c_messages_dir.get_value();
		}
		else
		{
			std::string dir = Poco::Path(root_dir).append(c_messages_dir.get_value()).toString();
			output_dir = dir;
		}

		set_output_dir(output_dir);
	}
}

bool protobuf_file_emitter::emit(const std::shared_ptr<serialized_buffer>& data)
{
	if (!should_dump(data))
	{
		LOG_DEBUG("Not emitting (should_dump==false)");
		return false;
	}

	return emit_raw(data);
}

bool protobuf_file_emitter::should_dump(const std::shared_ptr<serialized_buffer>& data) const
{
	return (m_message_type_nums.empty() ||
	        m_message_type_nums.find(data->message_type) != m_message_type_nums.end());
}
}  // namespace dragent
