#include "metric_limits.h"
#include <fnmatch.h>
#include <limits>

const int metric_limits::ML_NO_FILTER_POSITION = std::numeric_limits<int>::max();

metric_limits::metric_limits(const metrics_filter_vec filters, uint64_t max_entries,
							uint64_t expire_seconds, unsigned log_seconds):
							m_filters(filters),
							m_max_entries(max_entries),
							m_purge_seconds(expire_seconds),
							m_log_seconds(log_seconds)
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
#endif // HAS_ANALYZER
	optimize_exclude_all(m_filters);
	time(&m_last_purge);
	time(&m_last_log);
}

void metric_limits::log()
{
#ifdef HAS_ANALYZER
	if(g_logger.get_severity() >= sinsp_logger::SEV_DEBUG)
	{
		std::ostringstream os;
		os << "Metrics permission list:" << std::endl;
		for(auto& c : m_cache)
		{
			os << (c.second.get_allow() ? "+ included: " : "- excluded: ") << c.first << std::endl;
		}
		g_logger.log(os.str(), sinsp_logger::SEV_DEBUG);
	}
#endif // HAS_ANALYZER
	time(&m_last_log);
	// this can be the reason for log only once
	if(m_first_log)
	{
		m_first_log = false;
	}
}

// for testing purposes only
void metric_limits::log(std::ostream& os)
{
	if(log_time())
	{
		os << "Metrics permission list:" << std::endl;
		for(auto& c : m_cache)
		{
			os << c.first << ':' << (c.second.get_allow() ? " included" : " excluded") << std::endl;
		}
		time(&m_last_log);
	}
}

bool metric_limits::allow(const std::string& metric, int* pos)
{
	if(log_time()) { log(); }
	auto found = m_cache.find(metric);
	if(found != m_cache.end())
	{
		if(pos) { *pos = found->second.position(); }
		return found->second.get_allow();
	}

	int p = 0;
	for(const auto& f : m_filters)
	{
		++p;
		int m = fnmatch(f.filter().c_str(), metric.c_str(), FNM_CASEFOLD);
		if(0 == m)
		{
			insert(metric, f.included(), p);
			if(pos) { *pos = p; }
			return f.included();
		}
		else if(FNM_NOMATCH != m)
		{
#ifdef HAS_ANALYZER
			g_logger.format(sinsp_logger::SEV_WARNING, "Metric limits: error glob matching [%s] "
					  "with pattern [%s]", metric.c_str(), f.filter().c_str());
#endif // HAS_ANALYZER
		}
	}

	insert(metric, true, ML_NO_FILTER_POSITION);
	if(pos) { *pos = ML_NO_FILTER_POSITION; }
	return true;
}

void metric_limits::insert(const std::string& metric, bool value, int pos)
{
	purge_cache();
	if(m_cache.size() < m_max_entries)
	{
		m_cache.insert({metric, entry(value, pos)});
	}
	else
	{
#ifdef HAS_ANALYZER
		g_logger.format(sinsp_logger::SEV_WARNING, "Metric limit cache full, metric [%s] "
				  "will not be cached.", metric.c_str());
#endif // HAS_ANALYZER
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
