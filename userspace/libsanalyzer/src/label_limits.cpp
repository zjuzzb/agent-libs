#include "label_limits.h"

label_limits::label_limits(filter_vec_t&& filters,
			   uint32_t max_entries,
			   uint64_t expire_seconds)
	: user_configured_limits(std::forward<filter_vec_t>(filters),
				 "Labels",
				 log_flags<label_limits>::m_log,
				 log_flags<label_limits>::m_enable_log,
				 log_flags<label_limits>::m_last,
				 log_flags<label_limits>::m_running,
				 max_entries,
				 expire_seconds)
{
}

label_limits::sptr_t label_limits::build(
	filter_vec_t filters,
	bool log_enabled,
	uint32_t max_entries,
	uint64_t expire_seconds)
{
	if(log_enabled)
	{
		user_configured_limits::enable_logging<label_limits>();
	}
	if(!filters.empty() && !label_limits::first_includes_all(filters))
	{
		return std::make_shared<label_limits>(std::move(filters), max_entries, expire_seconds);
	}
	return nullptr;
}

INITIALIZE_LOG(label_limits);


