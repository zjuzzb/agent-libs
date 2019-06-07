#include "filter_limits.h"

user_configured_limits::user_configured_limits(const filter_vec_t& filters,
					       const std::string& target_name,
					       bool& log_ref,
					       bool& enable_log_ref,
					       time_t& last_ref,
					       time_t& running_ref,
					       uint32_t max_entries,
					       uint64_t expire_seconds)
	: m_filters(filters),
	m_max_entries(max_entries),
	m_purge_seconds(expire_seconds),
	m_target_type_name(target_name),
	m_log_flags_ref(log_ref, enable_log_ref, last_ref, running_ref)
{
	optimize_exclude_all(m_filters);
	time(&m_last_purge);
}

user_configured_limits::~user_configured_limits()
{
}

void user_configured_limits::insert(const std::string& target, const user_configured_filter& filter, bool value, int pos)
{
	if(m_max_entries) // caching enabled
	{
		purge_cache();
		if(m_cache.size() < m_max_entries)
		{
			m_cache.insert({target, entry(value, filter, pos)});
		}
		else
		{
			g_logger.format(sinsp_logger::SEV_WARNING, "Metric limit cache full, metric [%s] "
					  "will not be cached.", target.c_str());
		}
	}
}

void user_configured_limits::purge_cache()
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

user_configured_limits::entry::entry(bool allow, ::user_configured_filter f, int pos)
	: m_allow(allow), m_filter(f), m_pos(pos)
{
	access();
}

void user_configured_limits::log( const std::string& target,
				  const std::string& type,
				  const std::string& target_type_name,
				  bool inc,
				  bool log_enabled,
				  std::string&& filter)
{
	if(log_enabled)
	{
		g_logger.format(sinsp_logger::SEV_INFO, "%c[%s] %s %s: %s (%s)",
				(inc ? '+' : '-'),
				type.c_str(),
				target_type_name.c_str(),
				(inc ? "included" : "excluded"),
				target.c_str(),
				filter.c_str());
	}
}

bool user_configured_limits::log_targets(uint32_t interval, uint32_t duration)
{
	return _log_targets(m_log_flags_ref.m_enable_log,
			    m_log_flags_ref.m_last,
			    m_log_flags_ref.m_running,
			    interval,
			    duration);
}

void user_configured_limits::check_log_required()
{
	m_log_flags_ref.m_log = log_targets();
}

bool user_configured_limits::allow(const std::string& target, std::string& filter, int* pos, const std::string& type)
{
	filter.clear();
	if(m_max_entries)
	{
		auto found = m_cache.find(target);
		if(found != m_cache.end())
		{
			if(pos) { *pos = found->second.position(); }
			filter = found->second.filter();
			bool inc = found->second.get_allow();
			if(!pos)
			{
				check_log_required();
				log(target,
				    type,
				    m_target_type_name,
				    inc,
				    m_log_flags_ref.m_log,
				    wrap_filter(filter, inc));
			}
			return inc;
		}
	}

	int p = 0;
	for(const auto& f : m_filters)
	{
		++p;
		int m = fnmatch(f.to_string().c_str(), target.c_str(), FNM_CASEFOLD);
		if(0 == m)
		{
			bool inc = f.included();
			insert(target, f, inc, p);
			if(pos) { *pos = p; }
			filter = f.to_string();
			if(!pos)
			{
				check_log_required();
				log(target,
				    type,
				    m_target_type_name,
				    f.included(),
				    m_log_flags_ref.m_log,
				    wrap_filter(filter, inc));
			}
			return inc;
		}
		else if(FNM_NOMATCH != m)
		{
			g_logger.format(sinsp_logger::SEV_WARNING,
					"%s limits: error glob matching [%s] with pattern [%s]",
					m_target_type_name.c_str(),
					target.c_str(),
					f.to_string().c_str());
		}
	}

	insert(target, {"", true}, true, NO_FILTER_POSITION);
	if(pos) { *pos = NO_FILTER_POSITION; }
	if(!pos)
	{
		check_log_required();
		log(target,
		    type,
		    m_target_type_name,
		    true,
		    m_log_flags_ref.m_log,
		    wrap_filter(" ", true));
	}
	return true;
}


bool user_configured_limits::_log_targets(bool log_enabled,
					  time_t& last,
					  time_t& running,
					  uint32_t interval,
					  uint32_t duration)
{
	if(!log_enabled)
	{
		return false;
	}

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
