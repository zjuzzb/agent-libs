#define __STDC_FORMAT_MACROS
#include "metrics_file_emitter.h"

namespace dragent
{

metrics_file_emitter::metrics_file_emitter()
{
}

bool metrics_file_emitter::emit_message_to_file(const google::protobuf::Message& msg)
{
	if (!should_dump())
	{
		return false;
	}

	return emit_message(msg);
}

bool metrics_file_emitter::emit_metrics_to_file(const std::shared_ptr<flush_data_message>& data)
{
	if (!should_dump())
	{
		return false;
	}

	return emit_text(data);
}

bool metrics_file_emitter::emit_metrics_to_json_file(
    const std::shared_ptr<flush_data_message>& data)
{
	if (!should_dump())
	{
		return false;
	}

	return emit_json(data);
}

bool metrics_file_emitter::get_emit_metrics_to_file() const
{
	return !get_metrics_directory().empty();
}

void metrics_file_emitter::set_metrics_directory(const std::string& dir)
{
	// needs to be locked so user doesn't get bogus dir before we've "sanitized" it
	std::unique_lock<std::mutex> lock(m_metrics_dir_mutex);

	set_output_dir(dir);
}

std::string metrics_file_emitter::get_metrics_directory() const
{
	std::unique_lock<std::mutex> lock(m_metrics_dir_mutex);

	return get_output_dir();
}

bool metrics_file_emitter::should_dump() const
{
	return !get_metrics_directory().empty();
}
}
