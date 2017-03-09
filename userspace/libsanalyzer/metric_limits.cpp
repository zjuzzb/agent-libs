#include "metric_limits.h"
#ifdef HAS_ANALYZER
#include "sinsp.h"
#include "sinsp_int.h"
#endif // HAS_ANALYZER
#include <fnmatch.h>

metric_limits::metric_limits(const std::vector<std::string>& excluded, const std::vector<std::string>& included,
							uint64_t max_entries, uint64_t expire_seconds):
							m_max_entries(max_entries),
							m_purge_seconds(expire_seconds)
{
	time(&m_last_purge);
	time(&m_last_log);
#ifndef DENSE_HASH_MAP
	m_cache.reserve(m_max_entries);
#endif
	for(const auto& i : included)
	{
		m_filters.emplace_back(std::make_pair(i, true));
	}
	for(const auto& e : excluded)
	{
		m_filters.emplace_back(std::make_pair(e, false));
	}
#ifdef HAS_ANALYZER
	ASSERT(m_filters.size());
#endif // HAS_ANALYZER
}

void metric_limits::log()
{
#ifdef HAS_ANALYZER
	if(g_logger.get_severity() >= sinsp_logger::SEV_DEBUG)
	{
		std::ostringstream os;
		os << "Allowed metrics:" << std::endl;
		for(auto& c : m_cache)
		{
			os << c.first << ':' << (c.second.get_allow() ? "true" : "false") << std::endl;
		}
		g_logger.log(os.str(), sinsp_logger::SEV_DEBUG);
	}
#endif // HAS_ANALYZER
	time(&m_last_log);
}

bool metric_limits::allow(const std::string& metric)
{
	if(last_log() > m_log_seconds) { log(); }
	auto found = m_cache.find(metric);
	if(found != m_cache.end())
	{
		return found->second.get_allow();
	}

	for(const auto& f : m_filters)
	{
		int m = fnmatch(f.first.c_str(), metric.c_str(), FNM_CASEFOLD);
		if(0 == m)
		{
			insert(metric, f.second);
			return f.second;
		}
		else if(FNM_NOMATCH != m)
		{
			SINSP_LOG("Metric limits: error glob matching [" + metric + "] "
					  "with pattern [" + f.first + ']', SEV_WARNING);
		}
	}

	insert(metric, true);
	return true;
}

void metric_limits::insert(const std::string& metric, bool value)
{
	purge_cache();
	if(m_cache.size() < m_max_entries)
	{
		m_cache.insert({metric, entry(value)});
	}
	else
	{
		SINSP_LOG("Metric limit cache full, metric [" + metric + "] "
				  "will not be cached.", SEV_DEBUG);
	}
}

void metric_limits::purge_cache()
{
	if(m_cache.size() > purge_limit() && last_purge() > m_purge_seconds)
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
