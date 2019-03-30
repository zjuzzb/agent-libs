#pragma once

#include <memory>
#include <chrono>
#include <iostream>
#include "utils.h"

class sinsp_evttables;

///////////////////////////////////////////////////////////////////////////////
// Hashing support for stl pairs
///////////////////////////////////////////////////////////////////////////////
namespace std
{
  template<typename S, typename T> struct hash<pair<S, T>>
  {
    inline size_t operator()(const pair<S, T> & v) const
    {
      size_t seed = 0;
      ::hash_combine(seed, v.first);
      ::hash_combine(seed, v.second);
      return seed;
    }
  };
}

///////////////////////////////////////////////////////////////////////////////
// Hashing support for ipv4tuple
// XXX for the moment, this has not been optimized for performance
///////////////////////////////////////////////////////////////////////////////
struct ip4t_hash
{
	size_t operator()(ipv4tuple t) const
	{
		size_t seed = 0;

		std::hash<uint64_t> hasher64;
		std::hash<uint32_t> hasher32;
		std::hash<uint8_t> hasher8;

		seed ^= hasher64(*(uint64_t*)t.m_all) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
		seed ^= hasher32(*(uint32_t*)(t.m_all + 8)) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
		seed ^= hasher8(*(uint8_t*)(t.m_all + 12)) + 0x9e3779b9 + (seed << 6) + (seed >> 2);

		return seed;
	}
};

struct ip4t_cmp
{
	bool operator () (ipv4tuple t1, ipv4tuple t2) const
	{
		return (memcmp(t1.m_all, t2.m_all, sizeof(t1.m_all)) == 0);
	}
};

///////////////////////////////////////////////////////////////////////////////
// Hashing support for unix_tuple
// not yet optimized
///////////////////////////////////////////////////////////////////////////////
struct unixt_hash
{
	size_t operator()(unix_tuple t) const
	{
		size_t seed = 0;

		std::hash<uint64_t> hasher64;

		seed ^= hasher64(*(uint64_t*)t.m_all) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
		seed ^= hasher64(*(uint64_t*)(t.m_all + 8)) + 0x9e3779b9 + (seed << 6) + (seed >> 2);

		return seed;
	}
};

struct unixt_cmp
{
	bool operator () (unix_tuple t1, unix_tuple t2) const
	{
		return (memcmp(t1.m_all, t2.m_all, sizeof(t1.m_all)) == 0);
	}
};

inline bool sinsp_strcmpi(const char* buf1, const char* buf2, size_t count)
{
	size_t j = count;

	while(--j)
	{
		//
		// Note: '| 0x20' converts to lowercase
		//
		if(((*buf1) | 0x20) != ((*buf2) | 0x20))
		{
			return false;
		}

		buf1++;
		buf2++;
	}

	return true;
}

inline void debug_print_binary_buf(char* buf, uint64_t bufsize)
{
	for (unsigned int j=0; j< bufsize; ++j)
	{
		if(buf[j] >= 'A' && buf[j] <= 'z' )
		{
			printf("\x1B[31m%c\x1B[0m",buf[j]);
		}
		else
		{
			printf("%02x",(uint8_t)buf[j]);
		}
	}
}

inline std::string truncate_str(const std::string& s, uint32_t max_size)
{
	if (s.size() <= max_size)
	{
		return s;
	}
	else
	{
		std::string truncated(s, 0, max_size-3);
		truncated += "...";
		return truncated;
	}
}

#ifndef _WIN32
template<typename T, typename... Ts>
std::unique_ptr<T> make_unique(Ts&&... params)
{
	return std::unique_ptr<T>(new T(std::forward<Ts>(params)...));
}
#endif // _WIN32

#ifdef SIMULATE_DROP_MODE
bool should_drop(sinsp_evt *evt);
#endif

/**
 * This class allows you to count time used by some function in an easy way
 * you can use it in two ways:
 *
 * 1. scoped
 *
 * {
 *   stopwatch watch("My block of code");
 *   ...
 * }
 *
 * 2. or by manually calling start() and stop()
 *
 * {
 *   stopwatch watch;
 *   watch.start("1st part");
 *   ...
 *   watch.stop();
 *   watch.start("2nd part"):
 *   ...
 *   watch.stop();
 * }
 */
class stopwatch
{
public:
	stopwatch() {}

	stopwatch(std::string&& name):
			m_name(name),
			m_starttime(std::chrono::system_clock::now()),
			m_started(true)
	{
	}

	~stopwatch()
	{
		if(m_started)
		{
			stop();
		}
	}

	void start(std::string&& name)
	{
		m_name = name;
		m_starttime = std::chrono::system_clock::now();
		m_started = true;
	}

	void stop()
	{
		m_endtime = std::chrono::system_clock::now();
		auto d = std::chrono::duration_cast<std::chrono::microseconds>(m_endtime - m_starttime);
		std::cerr << m_name << " took " << d.count() << " us" << std::endl;
		m_started = false;
	}


private:
	std::string m_name;
	std::chrono::system_clock::time_point m_starttime;
	std::chrono::system_clock::time_point m_endtime;
	bool m_started;
};

/**
 * Often we need to run something on an interval
 * usually we need to store last_run_ts compare to now
 * and run it
 * This micro-class makes this easier
 */
class run_on_interval
{
public:
	inline run_on_interval(uint64_t interval);

	template<typename Callable>
	inline void run(const Callable& c, uint64_t now = sinsp_utils::get_current_time_ns());
	uint64_t interval() const { return m_interval; }
	void interval(uint64_t i) { m_interval = i; }
private:
	uint64_t m_last_run_ns;
	uint64_t m_interval;
};

run_on_interval::run_on_interval(uint64_t interval):
		m_last_run_ns(0),
		m_interval(interval)
{
}

template<typename Callable>
void run_on_interval::run(const Callable& c, uint64_t now)
{
	if(now - m_last_run_ns > m_interval)
	{
		c();
		m_last_run_ns = now;
	}
}

template<typename T>
class threshold_filter
{
public:
	threshold_filter(const char* desc, T threshold, unsigned ntimes):
			m_desc(desc),
			m_threshold(threshold),
			m_ntimes(0),
			m_ntimes_max(ntimes)
	{
	}

	threshold_filter(const char* desc):
			m_desc(desc),
			m_threshold(0),
			m_ntimes(0),
			m_ntimes_max(0)
	{
	}

	template<typename Callable>
	inline void run_on_threshold(T v, const Callable& trigger)
	{
		if(m_ntimes_max == 0)
		{
			return;
		}
		if(v > m_threshold)
		{
			m_ntimes += 1;
			log(v);
			if(m_ntimes >= m_ntimes_max)
			{
				trigger();
				m_ntimes = 0;
			}
		}
		else
		{
			m_ntimes = 0;
		}
	}

	void set_ntimes_max(unsigned value)
	{
		m_ntimes_max = value;
	}

	void set_threshold(T value)
	{
		m_threshold = value;
	}

private:
	void log(T value);
	const char* m_desc;
	T m_threshold;
	unsigned m_ntimes;
	unsigned m_ntimes_max;
};

// returns process rss in kb and cpu in [% * 100]
bool get_proc_mem_and_cpu(long& kb, int& cpu, std::string* err = nullptr);

#ifndef CYGWING_AGENT
class nsenter
{
public:
	nsenter(int pid, const std::string& type);
	virtual ~nsenter();

private:
	int open_ns_fd(int pid, const std::string& type);
	static std::unordered_map<std::string, int> m_home_ns;
	std::string m_type;
};
#endif // CYGWING_AGENT

class ratelimit {
public:
	ratelimit(): m_burst(1), m_hits(0), m_interval(60000000000), m_start_ns(0) { }
	ratelimit(unsigned int burst): m_burst(burst), m_hits(0), m_interval(60000000000), m_start_ns(0) { }
	ratelimit(unsigned int burst, uint64_t interval): m_burst(burst), m_hits(0), m_interval(interval), m_start_ns(0) { }
	template<typename Callable>
	inline void run(const Callable& c, uint64_t now = sinsp_utils::get_current_time_ns());

private:
	unsigned int m_burst;
	unsigned int m_hits;
	uint64_t m_interval;
	uint64_t m_start_ns;
};


template<typename Callable>
void ratelimit::run(const Callable& c, uint64_t now)
{
	if (!m_start_ns)
	{
		m_start_ns = now;
	}

	if (now > m_start_ns + m_interval)
	{
		m_start_ns = now;
		m_hits = 0;
	}

	if (m_burst && m_burst > m_hits)
	{
		++m_hits;
		c();
	}
}

const uint64_t MSECS_PER_SEC = 1000L;
const uint64_t USECS_PER_SEC = 1000L * 1000;
const uint64_t NSECS_PER_SEC = 1000L * 1000 * 1000;
