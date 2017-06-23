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

// suppress deprecated warnings for auto_ptr in boost
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <yaml-cpp/yaml.h>
#pragma GCC diagnostic pop

#endif // HAS_ANALYZER



class metrics_filter
{
public:
	typedef std::shared_ptr<std::string> sptr_t;

	metrics_filter()
	{}
	metrics_filter(const std::string& filter, bool included): m_filter(std::make_shared<std::string>(filter)), m_included(included)
	{}
	sptr_t filter() const { return m_filter; }
	bool included() const { return m_included; }
	void set_filter(const std::string& filter)
	{
		m_filter = std::make_shared<std::string>(filter);
	}
	void set_included(bool included)
	{
		m_included = included;
	}
private:
	sptr_t m_filter;
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
	typedef metrics_filter::sptr_t filter_sptr_t;

	static const int ML_NO_FILTER_POSITION;

	class entry
	{
	public:
		entry() = delete;
		entry(bool allow, filter_sptr_t filter, int pos);
		void set_allow(bool a = true);
		bool get_allow();
		std::string filter() const;
		int position() const;
		double last_access() const;

	private:
		void access();

		bool m_allow = true;
		filter_sptr_t m_filter;
		int m_pos = metric_limits::ML_NO_FILTER_POSITION;
		time_t m_access = 0;
	};

	typedef std::unordered_map<std::string, entry> map_t;

	metric_limits() = delete;
	metric_limits(metrics_filter_vec filters,
				  unsigned max_entries = 0,
				  uint64_t expire_seconds = 86400);

	bool allow(const std::string& metric, std::string& filter, int* pos = nullptr, const std::string& type = "");
	bool has(const std::string& metric) const;
	uint64_t cached();
	void purge_cache();
	void clear_cache();
	unsigned cache_max_entries() const;
	uint64_t cache_expire_seconds() const;

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

	static bool log_metrics(int interval = 30, int duration = 10);
	static bool log_enabled();
	static void enable_log();
	static void disable_log();
	static void log(const std::string& metric, const std::string& type, bool inc, bool log_enabled, std::string&& filter);
	static void enable_logging()
	{
		m_enable_log = true;
	}

private:
	void insert(const std::string& metric, filter_sptr_t filter, bool value, int pos);
	double secs_since_last_purge() const;
	uint64_t purge_limit();
	std::string wrap_filter(const std::string& filter, bool inc);
	double secs_since_last_log() const;
	void log();

	metrics_filter_vec m_filters;
	map_t m_cache;
	unsigned m_max_entries = 0;
	time_t m_last_purge = 0;
	uint64_t m_purge_seconds = 86400; // 24hr
	static bool m_log; // used to enter/exit log periods
	static bool m_enable_log; // flag for logging being configured
};

inline void metric_limits::log(const std::string& metric, const std::string& type, bool inc, bool log_enabled, std::string&& filter)
{
	if(log_enabled)
	{
#ifdef HAS_ANALYZER
		g_logger.format(sinsp_logger::SEV_INFO, "%c[%s] metric %s: %s (%s)",
					(inc ? '+' : '-'), type.c_str(), (inc ? "included" : "excluded"), metric.c_str(), filter.c_str());
#endif
	}
}

inline std::string metric_limits::wrap_filter(const std::string& filter, bool inc)
{
	std::string ret("filter: ");
	ret.append(1, (inc ? '+' : '-')).append(1, '[').append(filter.empty() ? std::string(1, ' ') : filter).append(1, ']');
	return ret;
}

inline void metric_limits::enable_log()
{
	m_log = log_metrics();
}

inline void metric_limits::disable_log()
{
	m_log = false;
}

inline bool metric_limits::log_enabled()
{
	return m_log;
}

inline bool metric_limits::first_includes_all(metrics_filter_vec v)
{
	ASSERT(!v.size() || v[0].filter());
	return (v.size() && v[0].included() && v[0].filter() &&
		   (v[0].filter()->empty() ||
		   ((v[0].filter()->size() == 1) && ((*v[0].filter())[0] == '*'))));
}

inline void metric_limits::optimize_exclude_all(metrics_filter_vec& filters)
{
	// if first filter prohibits all, it's pointless to have any other entries, so let's optimize it away
	if(filters.size() > 1)
	{
		metrics_filter& f = filters[0];
		ASSERT(f.filter());
		if(!f.included() && f.filter() && f.filter()->size() == 1 && (*f.filter())[0] == '*')
		{
			filters.erase(filters.begin() + 1, filters.end());
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

inline unsigned metric_limits::cache_max_entries() const
{
	return m_max_entries;
}

inline uint64_t metric_limits::cache_expire_seconds() const
{
	return m_purge_seconds;
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

inline std::string metric_limits::entry::filter() const
{
	return m_filter ? *m_filter : "";
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


// filter used for mount points is same as for the metric limits
typedef std::vector<metrics_filter> mount_points_filter_vec;

class mount_points_limits
{
public:

	typedef std::shared_ptr<mount_points_limits> sptr_t;

	mount_points_limits() = default;
	mount_points_limits(const mount_points_limits&) = delete;
	mount_points_limits(const mount_points_filter_vec& filters, unsigned limit_size);
	~mount_points_limits() = default;

	bool allow(const std::string& device,
				const std::string& fs_type,
				const std::string& mount_dir);
	bool increase();
	void reset();
	mount_points_filter_vec get_filters() const { return m_filters; }

private:

	mount_points_filter_vec m_filters;
	const unsigned m_limit_size;
	unsigned m_current_size;
	bool m_limit_logged;
};
