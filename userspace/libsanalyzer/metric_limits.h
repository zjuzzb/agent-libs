#pragma once

#include <vector>
#include <unordered_map>
#include <string>
#include <ctime>
#include <cmath>
#include <memory>
#include <iostream>

#ifdef HAS_ANALYZER
#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_settings.h"
#define ML_CACHE_SIZE STATSD_METRIC_HARD_LIMIT + APP_METRICS_HARD_LIMIT + 2*JMX_METRICS_HARD_LIMIT + 1000

// suppress deprecated warnings for auto_ptr in boost
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <yaml-cpp/yaml.h>
#pragma GCC diagnostic pop

#else

#define ML_CACHE_SIZE 9000

#endif // HAS_ANALYZER



class metrics_filter
{
public:
	metrics_filter()
	{}
	metrics_filter(std::string filter, bool included): m_filter(filter), m_included(included)
	{}
	const std::string& filter() const { return m_filter; }
	bool included() const { return m_included; }
	void set_filter(const std::string& filter)
	{
		m_filter = filter;
	}
	void set_included(bool included)
	{
		m_included = included;
	}
private:
	std::string m_filter;
	bool m_included = true;
};

typedef std::vector<metrics_filter> metrics_filter_vec;

#ifdef HAS_ANALYZER

namespace YAML
{
	template<>
	struct convert<metrics_filter>
	{
		static bool decode(const Node& node, metrics_filter& rhs)
		{
			if(node["include"])
			{
				rhs.set_included(true);
				rhs.set_filter(node["include"].as<std::string>());
				return true;
			}
			else if(node["exclude"])
			{
				rhs.set_included(false);
				rhs.set_filter(node["exclude"].as<std::string>());
				return true;
			}
			return false;
		}
	};
}

#endif // HAS_ANALYZER

class metric_limits
{
public:
	typedef std::shared_ptr<metric_limits> sptr_t;
	typedef const std::shared_ptr<metric_limits>& cref_sptr_t;

	static const int ML_NO_FILTER_POSITION;

	class entry
	{
	public:
		entry() = delete;
		entry(bool allow, int pos);
		void set_allow(bool a = true);
		bool get_allow();
		int position() const;
		double last_access() const;

	private:
		void access();

		bool m_allow = true;
		int m_pos = metric_limits::ML_NO_FILTER_POSITION;
		time_t m_access = 0;
	};

	typedef std::unordered_map<std::string, entry> map_t;

	metric_limits() = delete;
	metric_limits(metrics_filter_vec filters,
				  uint64_t max_entries = ML_CACHE_SIZE,
				  uint64_t expire_seconds = 86400,
				  unsigned log_seconds = 300);

	bool allow(const std::string& metric, int* pos = nullptr);
	bool has(const std::string& metric) const;
	uint64_t cached();
	void purge_cache();
	void clear_cache();
	uint64_t cache_max_entries() const;
	uint64_t cache_expire_seconds() const;
	unsigned cache_log_seconds() const;

	//
	// Used to check whether filter is actually worth creating;
	//
	// Returns true on:
	//
	// metrics_filter:
	//   - included: *
	//  [- ...]
	//
	// and
	//
	// metrics_filter:
	//   - included:
	//  [- ...]
	//
	static bool first_includes_all(metrics_filter_vec v);

	// If it has more than one entry, reduce filter list with first rule
	// "exclude all" to one entry
	static void optimize_exclude_all(metrics_filter_vec& filter);

	// for testing purposes only
	void log(std::ostream& os);

	double secs_since_creation() const;
	void set_first_log();

private:
	void insert(const std::string& metric, bool value, int pos);
	double secs_since_last_purge() const;
	uint64_t purge_limit();

	bool log_time() const;
	double secs_since_last_log() const;
	void log();

	metrics_filter_vec m_filters;
	map_t m_cache;
	uint64_t m_max_entries = ML_CACHE_SIZE;
	time_t m_last_purge = 0;
	uint64_t m_purge_seconds = 86400; // 24hr
	time_t m_last_log = 0;
	unsigned m_log_seconds = 300; // 5min
	bool m_first_log = false;
};

inline bool metric_limits::first_includes_all(metrics_filter_vec v)
{
	return (v.size() && v[0].included() &&
		   (v[0].filter().empty() ||
		   ((v[0].filter().size() == 1) && (v[0].filter()[0] == '*'))));
}

inline void metric_limits::optimize_exclude_all(metrics_filter_vec& filters)
{
	// if first filter prohibits all, it's pointless to have any other entries, so let's optimize it away
	if(filters.size() > 1)
	{
		metrics_filter& f = filters[0];
		if(!f.included() && f.filter().size() == 1 && f.filter()[0] == '*')
		{
			filters = {{"*", false}};
		}
	}
}

inline bool metric_limits::has(const std::string& metric) const
{
	return (m_cache.find(metric) != m_cache.end());
}

inline uint64_t metric_limits::cached()
{
	purge_cache();
	return m_cache.size();
}

inline void metric_limits::clear_cache()
{
	m_cache.clear();
}

inline uint64_t metric_limits::purge_limit()
{
	return static_cast<uint64_t>(round((double)m_max_entries * 2 / 3));
}

inline double metric_limits::secs_since_last_purge() const
{
	time_t now; time(&now);
	return difftime(now, m_last_purge);
}

inline bool metric_limits::log_time() const
{
	return (secs_since_last_log() > m_log_seconds) || m_first_log;
}

inline double metric_limits::secs_since_last_log() const
{
	time_t now; time(&now);
	return difftime(now, m_last_log);
}

inline double metric_limits::secs_since_creation() const
{
	return secs_since_last_log();
}

inline void metric_limits::set_first_log()
{
	m_first_log = true;
}

inline uint64_t metric_limits::cache_max_entries() const
{
	return m_max_entries;
}

inline uint64_t metric_limits::cache_expire_seconds() const
{
	return m_purge_seconds;
}

inline unsigned metric_limits::cache_log_seconds() const
{
	return m_log_seconds;
}

inline metric_limits::entry::entry(bool allow, int pos): m_allow(allow), m_pos(pos)
{
	access();
}

inline void metric_limits::entry::set_allow(bool a)
{
	m_allow = a;
	access();
}

inline bool metric_limits::entry::get_allow()
{
	access();
	return m_allow;
}

inline int metric_limits::entry::position() const
{
	return m_pos;
}

inline void metric_limits::entry::access()
{
	time(&m_access);
}

inline double metric_limits::entry::last_access() const
{
	time_t now; time(&now);
	return difftime(now, m_access);
}
