#pragma once

#include "filter_limits.h"


class label_limits : public user_configured_limits
{
public:
	label_limits(const filter_vec_t& filters,
		     uint32_t max_entries = user_configured_limits::MAX_ENTRIES,
		     uint64_t expire_seconds = user_configured_limits::EXPIRE_SECONDS);

	virtual void sanitize_filters() override;

	bool allow(const std::string& target,
		   std::string& filter,
		   int* pos = nullptr,
		   const std::string& type = "");

	DEFINE_LOG("Labels");
	DEFINE_LOG_ENABLED(label_limits);
private:
};
