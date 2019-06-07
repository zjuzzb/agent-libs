#pragma once

#include <limits>
#include <unordered_map>
#include <vector>
#include <memory>
#include <fnmatch.h>
#include <type_traits>

#include "sinsp.h"
#include "sinsp_int.h"

// suppress deprecated warnings for auto_ptr in boost
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <yaml-cpp/yaml.h>
#pragma GCC diagnostic pop

class user_configured_filter
{
public:
	using sptr_t = std::shared_ptr<std::string>;

	user_configured_filter()
	{
	}

	user_configured_filter(const std::string& filter
			       , bool included)
		: m_filter(filter),
		  m_included(included)
	{
	}

	user_configured_filter(const user_configured_filter& other)
		: m_filter(other.m_filter),
		  m_included(other.m_included)
	{
	}

	const std::string& to_string() const
	{
		return m_filter;
	}

	bool included() const noexcept
	{
		return m_included;
	}

	void set_filter(const std::string& filter)
	{
		m_filter = filter;
	}

	void set_included(bool included)
	{
		m_included = included;
	}
private:
	std::string  m_filter;
	bool m_included = true;
};


using filter_vec_t = std::vector<user_configured_filter>;


namespace YAML
{
	template<>
	struct convert<user_configured_filter>
	{
		static bool decode(const Node& node, user_configured_filter& rhs)
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

class user_configured_limits
{
public:
	static const int NO_FILTER_POSITION = std::numeric_limits<int>::max();
	static const uint32_t MAX_ENTRIES = 0;
	static const uint64_t EXPIRE_SECONDS = 86400;
	static const uint32_t LOG_INTERVAL_SECONDS = 30;
	static const uint32_t LOG_DURATION_SECONDS = 10;

	class entry
	{
	public:
		entry() = delete;
		entry(bool allow, user_configured_filter f, int pos);
		void set_allow(bool a = true);
		bool get_allow();
		std::string filter() const;
		int position() const;
		double last_access() const;

	private:
		void access();

		bool m_allow = true;
		::user_configured_filter m_filter;
		int m_pos = user_configured_limits::NO_FILTER_POSITION;
		time_t m_access = 0;
	};

	using map_t = std::unordered_map<std::string, entry>;

	user_configured_limits(const filter_vec_t& filters,
			       const std::string& target_name,
			       bool& log_ref,
			       bool& enable_log_ref,
			       time_t& last_ref,
			       time_t& running_ref,
			       uint32_t max_entries = MAX_ENTRIES,
			       uint64_t expire_seconds = EXPIRE_SECONDS);


	virtual ~user_configured_limits();

	virtual void sanitize_filters() = 0;

	bool allow(const std::string& target,
		   std::string& filter,
		   int* pos = nullptr,
		   const std::string& type = "");

	bool has(const std::string& target) const;
	uint64_t cached();
	void purge_cache();
	void clear_cache();
	uint32_t cache_max_entries() const;
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
	static bool first_includes_all(const filter_vec_t& v);

	// If it has more than one entry, reduce filter list with first rule
	// "exclude all" to one entry
	static void optimize_exclude_all(filter_vec_t& filter);

	// logging and log period must be handled on a per derived class base.
	// To do this, static variables and static methods are wrapped in templates
	template<typename DERIVED_CLASS>
	static bool log_targets(uint32_t interval = LOG_INTERVAL_SECONDS,
				uint32_t duration = LOG_DURATION_SECONDS);
	bool log_targets(uint32_t interval = LOG_INTERVAL_SECONDS,
			 uint32_t duration = LOG_DURATION_SECONDS);

	template<typename DERIVED_CLASS>
	static bool log_enabled();

	template<typename DERIVED_CLASS>
	static void check_log_required();
	void check_log_required();

	template<typename DERIVED_CLASS>
	static void disable_log();

	static void log(const std::string& target,
			const std::string& type,
			const std::string& target_type_name,
			bool inc,
			bool log_enabled,
			std::string&& filter);

	template<typename DERIVED_CLASS>
	static void enable_logging()
	{
		log_flags<DERIVED_CLASS>::m_enable_log = true;
	}

protected:
	filter_vec_t& get_filters();
	void set_cache_max_entries(uint32_t val) noexcept;

	template<typename V>
	using nc_nr_filter_t = typename std::remove_cv<typename std::remove_reference<V>::type>::type;

	// Use template arg type deduction to enable both
	// move and copy semantic
	template<typename V>
	auto set_filters(V&& vec) -> typename std::enable_if<std::is_same<nc_nr_filter_t<V>, filter_vec_t>::value, void>::type;

	void set_purge_seconds(uint64_t purge_seconds) noexcept;
private:
	void insert(const std::string& target, const user_configured_filter& filter, bool value, int pos);
	double secs_since_last_purge() const;
	uint64_t purge_limit();
	std::string wrap_filter(const std::string& filter, bool inc);

	static bool _log_targets(bool log_enabled,
				 time_t& last,
				 time_t& running,
				 uint32_t interval = LOG_INTERVAL_SECONDS,
				 uint32_t duration = LOG_DURATION_SECONDS);

	filter_vec_t m_filters;
	map_t m_cache;
	uint32_t m_max_entries;
	time_t m_last_purge = 0;
	uint64_t m_purge_seconds;
	std::string m_target_type_name;

public:
	template<typename DERIVED_CLASS>
	struct log_flags
	{
		static bool m_log;
		static bool m_enable_log;
		static time_t m_last;
		static time_t m_running;
	};

private:
	struct log_flags_ref
	{
		log_flags_ref(bool& log, bool& enable_log, time_t& last, time_t& running)
			: m_log(log),
			  m_enable_log(enable_log),
			  m_last(last),
			  m_running(running)
		{
		}

		bool& m_log;
		bool& m_enable_log;
		time_t& m_last;
		time_t& m_running;
	};

	log_flags_ref m_log_flags_ref;
};

inline std::string user_configured_limits::wrap_filter(const std::string& filter, bool inc)
{
	std::string ret("filter: ");
	ret.append(1, (inc ? '+' : '-')).append(1, '[').append(filter.empty() ? std::string(1, ' ') : filter).append(1, ']');
	return ret;
}



template<typename DERIVED_CLASS>
bool user_configured_limits::log_targets(uint32_t interval, uint32_t duration)
{
	return _log_targets(log_flags<DERIVED_CLASS>::m_enable_log,
			    log_flags<DERIVED_CLASS>::m_last,
			    log_flags<DERIVED_CLASS>::m_running,
			    interval,
			    duration);
}

template<typename DERIVED_CLASS>
void user_configured_limits::check_log_required()
{
	log_flags<DERIVED_CLASS>::m_log = log_targets<DERIVED_CLASS>();
}

template<typename DERIVED_CLASS>
void user_configured_limits::disable_log()
{
	log_flags<DERIVED_CLASS>::m_log = false;
}

template<typename DERIVED_CLASS>
bool user_configured_limits::log_enabled()
{
	return log_flags<DERIVED_CLASS>::m_log;
}

inline bool user_configured_limits::first_includes_all(const filter_vec_t& v)
{
	bool ret = false;
	if(!v.empty())
	{
		ret = (v.size() && v[0].included() &&
		       (v[0].to_string().empty() ||
			((v[0].to_string().size() == 1) && (v[0].to_string()[0] == '*'))));
	}

	return ret;
}

inline void user_configured_limits::optimize_exclude_all(filter_vec_t& filters)
{
	// if first filter prohibits all, it's pointless to have any other entries, so let's optimize it away
	if(filters.size() > 1)
	{
		user_configured_filter& f = filters[0];
		if(!f.included() && f.to_string().size() == 1 && f.to_string()[0] == '*')
		{
			filters.erase(filters.begin() + 1, filters.end());
		}
	}
}

inline bool user_configured_limits::has(const std::string& metric) const
{
	return (m_cache.find(metric) != m_cache.end());
}

inline uint64_t user_configured_limits::cached()
{
	purge_cache();
	return m_cache.size();
}

inline void user_configured_limits::clear_cache()
{
	m_cache.clear();
}

inline uint64_t user_configured_limits::purge_limit()
{
	return static_cast<uint64_t>(round((double)m_max_entries * 2 / 3));
}

inline double user_configured_limits::secs_since_last_purge() const
{
	time_t now; time(&now);
	return difftime(now, m_last_purge);
}

inline uint32_t user_configured_limits::cache_max_entries() const
{
	return m_max_entries;
}

inline void user_configured_limits::set_cache_max_entries(uint32_t val) noexcept
{
	m_max_entries = val;
}

inline 	void user_configured_limits::set_purge_seconds(uint64_t purge_seconds) noexcept
{
	m_purge_seconds = purge_seconds;
}

inline uint64_t user_configured_limits::cache_expire_seconds() const
{
	return m_purge_seconds;
}

inline 	filter_vec_t& user_configured_limits::get_filters()
{
	return m_filters;
}

inline void user_configured_limits::entry::set_allow(bool a)
{
	m_allow = a;
	access();
}

inline bool user_configured_limits::entry::get_allow()
{
	access();
	return m_allow;
}

inline std::string user_configured_limits::entry::filter() const
{
	return m_filter.to_string();
}

inline int user_configured_limits::entry::position() const
{
	return m_pos;
}

inline void user_configured_limits::entry::access()
{
	time(&m_access);
}

inline double user_configured_limits::entry::last_access() const
{
	time_t now; time(&now);
	return difftime(now, m_access);
}

template<typename V>
auto user_configured_limits::set_filters(V&& vec) -> typename std::enable_if<std::is_same<nc_nr_filter_t<V>, filter_vec_t>::value, void>::type
{
	// Move or copy depending whether an r-value or l-value is passed as arg
	m_filters = std::forward<V>(vec);
}

// Convenience macros to be used in derived classes
#define INITIALIZE_LOG(class)							\
	template<>								\
        bool user_configured_limits::log_flags<class>::m_log = false;		\
										\
        template<>								\
        bool user_configured_limits::log_flags<class>::m_enable_log = false;	\
										\
        template<>								\
        time_t user_configured_limits::log_flags<class>::m_last = 0;		\
										\
        template<>								\
        time_t user_configured_limits::log_flags<class>::m_running = 0;


#define DEFINE_LOG(tag)									\
	static void log(const std::string& target,					\
			const std::string& type,					\
			bool inc,							\
			bool log_enabled,						\
			std::string&& filter)						\
	{										\
		return user_configured_limits::log(target,				\
						   type,				\
						   tag,					\
						   inc,					\
						   log_enabled,				\
						   std::forward<std::string>(filter));	\
	}


#define DEFINE_LOG_ENABLED(class)							\
	static bool log_enabled()							\
        {										\
		return user_configured_limits::log_enabled<class>();			\
	}
