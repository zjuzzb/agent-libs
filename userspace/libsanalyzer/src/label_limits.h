#pragma once

#include "limits/filter_limits.h"


class label_limits : public user_configured_limits
{
public:
	using sptr_t = std::shared_ptr<label_limits>;

	explicit label_limits(filter_vec_t&& filters,
		     uint32_t max_entries = user_configured_limits::MAX_ENTRIES,
		     uint64_t expire_seconds = user_configured_limits::EXPIRE_SECONDS);

	static sptr_t build(filter_vec_t filters,
			   bool log_enabled,
			   uint32_t max_entries = user_configured_limits::MAX_ENTRIES,
			   uint64_t expire_seconds = user_configured_limits::EXPIRE_SECONDS);

	DEFINE_LOG("Labels");
	DEFINE_LOG_ENABLED(label_limits);
private:
};
