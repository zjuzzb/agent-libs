#include "metric_limits.h"
#include "Poco/Glob.h"
#include "sinsp.h"
#include "sinsp_int.h"

using Poco::Glob;

metric_limits::metric_limits(const list_t& excluded, const list_t& included,
							uint64_t max_entries, uint64_t expire_seconds):
							m_excluded(excluded),
							m_included(included),
							m_max_entries(max_entries),
							m_expire_seconds(expire_seconds)
{
	ASSERT(m_excluded.size() || m_included.size());
}

bool metric_limits::allow(const std::string& metric)
{
	auto found = m_cache.find(metric);
	if(found != m_cache.end())
	{
		return found->second.get_allow();
	}

	for(const auto& e : m_included)
	{
		Glob g(e, Glob::GLOB_CASELESS);
		if(g.match(metric))
		{
			insert(metric, true);
			return true;
		}
	}

	for(const auto& e : m_excluded)
	{
		Glob g(e, Glob::GLOB_CASELESS);
		if(g.match(metric))
		{
			insert(metric, false);
			return false;
		}
	}

	insert(metric, true);
	return true;
}

void metric_limits::purge_cache()
{
	if(m_cache.size() > m_max_entries * 2 / 3)
	{
		for(auto it = m_cache.begin(); it != m_cache.end();)
		{
			if(it->second.last_access() > m_expire_seconds)
			{
				it = m_cache.erase(it);
			}
			else { ++it; }
		}
	}
}
