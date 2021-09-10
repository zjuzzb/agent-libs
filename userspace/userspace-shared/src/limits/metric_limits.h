#pragma once

#include "filter_limits.h"

#include <memory>

class metric_limits : public user_configured_limits
{
public:
	using sptr_t = std::shared_ptr<metric_limits>;

	static const unsigned CUSTOM_METRICS_FILTERS_HARD_LIMIT;
	static const unsigned CUSTOM_METRICS_CACHE_HARD_LIMIT;

	metric_limits() = delete;
	explicit metric_limits(filter_vec_t&& filters,
		      uint32_t max_entries = user_configured_limits::MAX_ENTRIES,
		      uint64_t expire_seconds = user_configured_limits::EXPIRE_SECONDS);

	void sanitize_filters();

	static sptr_t build(filter_vec_t filters,
			   bool log_enabled,
			   uint32_t max_entries = user_configured_limits::MAX_ENTRIES,
			   uint64_t expire_seconds = user_configured_limits::EXPIRE_SECONDS);

	DEFINE_LOG("Metrics");
	DEFINE_LOG_ENABLED(metric_limits);
};
