#include "metric_limits.h"
#include <fnmatch.h>
#include <limits>

const int metric_limits::ML_NO_FILTER_POSITION = std::numeric_limits<int>::max();
bool metric_limits::m_log = false;
bool metric_limits::m_enable_log = false;

metric_limits::metric_limits(const metrics_filter_vec filters,
							unsigned max_entries,
							uint64_t expire_seconds):
							m_filters(filters),
							m_max_entries(max_entries),
							m_purge_seconds(expire_seconds)
{
#ifdef HAS_ANALYZER
	// Cases when we refuse to create object:
	// 1) empty filters
	// 2) filter list with first pattern being "allow all"
	// 3) number of filters exceeds max alowed limit
	// These cases are prevented in agent code, checks are here as shield from potential defects introduced in future changes.
	if(!m_filters.size())
	{
		throw sinsp_exception("An attempt to create metric limits with no filters detected.");
	}
	else if(first_includes_all(m_filters))
	{
		throw sinsp_exception("An attempt to create metric limits with 'allow all' (empty or '*') first pattern detected.");
	}
	else if(m_filters.size() > CUSTOM_METRICS_FILTERS_HARD_LIMIT)
	{
		std::ostringstream os;
		os << "An attempt to create metric limits with filter size (" << m_filters.size() << ") "
			"exceeding max allowed (" << CUSTOM_METRICS_FILTERS_HARD_LIMIT << ").";
		throw sinsp_exception(os.str());
	}
	if(m_max_entries > CUSTOM_METRICS_CACHE_HARD_LIMIT)
	{
		m_max_entries = CUSTOM_METRICS_CACHE_HARD_LIMIT;
		std::ostringstream os;
		os << "Metric limits max cache size (" << m_max_entries
			<< ") exceeded, reduced to " << CUSTOM_METRICS_CACHE_HARD_LIMIT;
		g_logger.log(os.str(), sinsp_logger::SEV_WARNING);
	}
#endif // HAS_ANALYZER
	optimize_exclude_all(m_filters);
	time(&m_last_purge);
}

bool metric_limits::log_metrics(int interval, int duration)
{
	if(!m_enable_log) { return false; }
	static time_t last;
	static time_t running;
	time_t now; time(&now);
	if((difftime(now, running) <= duration))
	{
		return true;
	}
	if((difftime(now, last) >= interval))
	{
		bool ret = (last != 0);
		time(&last);
		time(&running);
		return ret;
	}
	return false;
}

bool metric_limits::allow(const std::string& metric, std::string& filter, int* pos, const std::string& type)
{
	filter.clear();
	if(m_max_entries)
	{
		auto found = m_cache.find(metric);
		if(found != m_cache.end())
		{
			if(pos) { *pos = found->second.position(); }
			filter = found->second.filter();
			bool inc = found->second.get_allow();
			if(!pos) { log(metric, type, inc, m_log, wrap_filter(filter, inc)); }
			return inc;
		}
	}

	int p = 0;
	for(const auto& f : m_filters)
	{
		++p;
		int m = fnmatch(f.filter()->c_str(), metric.c_str(), FNM_CASEFOLD);
		if(0 == m)
		{
			bool inc = f.included();
			insert(metric, f.filter(), inc, p);
			if(pos) { *pos = p; }
			if(!pos) { log(metric, type, f.included(), m_log, wrap_filter(filter, inc)); }
			filter = (*f.filter());
			return inc;
		}
		else if(FNM_NOMATCH != m)
		{
#ifdef HAS_ANALYZER
			g_logger.format(sinsp_logger::SEV_WARNING, "Metric limits: error glob matching [%s] "
					  "with pattern [%s]", metric.c_str(), f.filter()->c_str());
#endif // HAS_ANALYZER
		}
	}

	insert(metric, nullptr, true, ML_NO_FILTER_POSITION);
	if(pos) { *pos = ML_NO_FILTER_POSITION; }
	if(!pos) { log(metric, type, true, m_log, wrap_filter(" ", true)); }
	return true;
}

void metric_limits::insert(const std::string& metric, filter_sptr_t filter, bool value, int pos)
{
	if(m_max_entries) // caching enabled
	{
		purge_cache();
		if(m_cache.size() < m_max_entries)
		{
			m_cache.insert({metric, entry(value, filter, pos)});
		}
		else
		{
	#ifdef HAS_ANALYZER
			g_logger.format(sinsp_logger::SEV_WARNING, "Metric limit cache full, metric [%s] "
					  "will not be cached.", metric.c_str());
	#endif // HAS_ANALYZER
		}
	}
}

void metric_limits::purge_cache()
{
	if(m_cache.size() > purge_limit() && secs_since_last_purge() > m_purge_seconds)
	{
	// Note: in theory, this is not guaranteed by standard to work before C++14
	// In practice, however, all relevant C++11 implementations honor the preservation
	// of relative order of non-erased elements, for details see https://goo.gl/pNXPYV
		for(auto it = m_cache.begin(); it != m_cache.end();)
		{
			if(it->second.last_access() > m_purge_seconds)
			{
				m_cache.erase(it++);
			}
			else { ++it; }
		}
		time(&m_last_purge);
	}
}

metric_limits::entry::entry(bool allow, filter_sptr_t filter, int pos):
	m_allow(allow), m_filter(filter), m_pos(pos)
{
	access();
}
