#pragma once

#include "filter_limits.h"


class label_limits : public user_configured_limits
{
public:
	explicit label_limits(filter_vec_t filters,
		     uint32_t max_entries = user_configured_limits::MAX_ENTRIES,
		     uint64_t expire_seconds = user_configured_limits::EXPIRE_SECONDS);

	void sanitize_filters() override;


	DEFINE_LOG("Labels");
	DEFINE_LOG_ENABLED(label_limits);
private:
};
