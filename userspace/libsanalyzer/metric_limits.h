#pragma once

#include "filter_limits.h"

#include <memory>

class metric_limits : public user_configured_limits
{
public:
	typedef std::shared_ptr<metric_limits> sptr_t;
	typedef const std::shared_ptr<metric_limits>& cref_sptr_t;
	typedef user_configured_filter::sptr_t filter_sptr_t;

	metric_limits() = delete;
	metric_limits(const filter_vec_t& filters,
		      uint32_t max_entries = user_configured_limits::MAX_ENTRIES,
		      uint64_t expire_seconds = user_configured_limits::EXPIRE_SECONDS);

	virtual void sanitize_filters() override;

	DEFINE_LOG("Metrics");
	DEFINE_LOG_ENABLED(metric_limits);
};


