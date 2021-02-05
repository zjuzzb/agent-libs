#pragma once

namespace draiosproto
{
static int32_t java_string_hash(const std::string& input, uint32_t end_pos = UINT32_MAX)
{
	int32_t hash = 0;

	if (end_pos > input.size())
	{
		end_pos = input.size();
	}

	for (uint32_t i = 0; i < end_pos; ++i)
	{
		hash = 31 * hash + input[i];
	}
	return hash;
}

static int32_t java_list_hash(const google::protobuf::RepeatedPtrField<std::string>& input)
{
	int32_t hash = 1;
	for (auto& i : input)
	{
		hash = 31 * hash + java_string_hash(i);
	}
	return hash;
}

// we have an awkward dependency that the BE depends on a hash of the program. This
// computes that hash, which is effectively the java hash of the equivalent objects
static size_t program_java_hasher(const draiosproto::program& input)
{
	const draiosproto::process& proc = input.procinfo();
	const draiosproto::process_details& details = proc.details();

	int32_t hash = 0;

	auto separator_loc = details.exe().find(": ");
	hash +=
	    java_string_hash(details.exe(),
	                     separator_loc == std::string::npos ? details.exe().size() : separator_loc);
	hash = 31 * hash + java_list_hash(details.args());
	hash += java_string_hash(details.container_id());
	hash += java_string_hash(input.environment_hash());

	return hash;
}
}  // namespace draiosproto
