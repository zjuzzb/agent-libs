#include "metric_limits.h"
#include <fnmatch.h>
#include <limits>
#include <algorithm>


metric_limits::metric_limits(filter_vec_t filters,
			     uint32_t max_entries,
			     uint64_t expire_seconds)
	: user_configured_limits(std::move(filters),
				 "Metrics",
				 log_flags<metric_limits>::m_log,
				 log_flags<metric_limits>::m_enable_log,
				 log_flags<metric_limits>::m_last,
				 log_flags<metric_limits>::m_running,
				 max_entries,
				 expire_seconds)
{
	sanitize_filters();
}

void metric_limits::sanitize_filters()
{
	// Cases when we refuse to create object:
	// 1) empty filters
	// 2) filter list with first pattern being "allow all"
	// 3) number of filters exceeds max alowed limit
	// These cases are prevented in agent code, checks are here as shield from potential defects introduced in future changes.
	if(!get_filters().size())
	{
		throw sinsp_exception("An attempt to create metric limits with no filters detected.");
	}
	else if(first_includes_all(get_filters()))
	{
		throw sinsp_exception("An attempt to create metric limits with 'allow all' (empty or '*') first pattern detected.");
	}
	else if(get_filters().size() > CUSTOM_METRICS_FILTERS_HARD_LIMIT)
	{
		std::ostringstream os;
		os << "An attempt to create metric limits with filter size (" << get_filters().size() << ") "
			"exceeding max allowed (" << CUSTOM_METRICS_FILTERS_HARD_LIMIT << ").";
		throw sinsp_exception(os.str());
	}
	if(cache_max_entries() > CUSTOM_METRICS_CACHE_HARD_LIMIT)
	{
		set_cache_max_entries(CUSTOM_METRICS_CACHE_HARD_LIMIT);
		std::ostringstream os;
		os << "Metric limits max cache size (" << cache_max_entries()
			<< ") exceeded, reduced to " << CUSTOM_METRICS_CACHE_HARD_LIMIT;
		g_logger.log(os.str(), sinsp_logger::SEV_WARNING);
	}
}

metric_limits::sptr_t metric_limits::build(
	filter_vec_t filters,
	bool log_enabled,
	uint32_t max_entries,
	uint64_t expire_seconds)
{
	if(log_enabled)
	{
		user_configured_limits::enable_logging<metric_limits>();
	}
	if(!filters.empty() && !metric_limits::first_includes_all(filters))
	{
		return std::make_shared<metric_limits>(std::move(filters), max_entries, expire_seconds);
	}
	return nullptr;
}

INITIALIZE_LOG(metric_limits);

