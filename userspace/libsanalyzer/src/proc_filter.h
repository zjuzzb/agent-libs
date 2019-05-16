#pragma once
#ifndef _WIN32

#include <string>
#include <set>
#include <vector>
#include "object_filter_config.h"

// suppress depreacated warnings for auto_ptr in boost
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <yaml-cpp/yaml.h>
#pragma GCC diagnostic pop


class sinsp_container_info;
class infrastructure_state;
class sinsp_threadinfo;

namespace proc_filter {
std::set<uint16_t> filter_ports(const std::set<uint16_t>& ports,
        const std::vector<object_filter_config::port_filter_rule>& rules);

class conf {
	static const bool default_enabled = false;
public:
	explicit conf(std::string context_str):
		m_context(std::move(context_str)),
		m_enabled(default_enabled)
	{}

	void set_enabled(bool val) { m_enabled = val; }
	bool enabled() const { return m_enabled; }
	static bool enabled_default() { return default_enabled; }

	void set_rules(std::vector<object_filter_config::filter_rule> rules) { m_rules = std::move(rules); }
	const std::vector<object_filter_config::filter_rule>& rules() const { return m_rules; }

#ifndef CYGWING_AGENT
	// match_rule() returns a boolean pair. The first indicates if the rule matched,
	// the second is the result of on_match(), if passed in, or m_include otherwise.
	std::pair<bool, bool> match_rule(const object_filter_config::filter_rule &rule,
					 int rule_num,
					 const sinsp_threadinfo *tinfo,
					 const sinsp_threadinfo *mtinfo,
					 const sinsp_container_info *container,
					 const infrastructure_state &is,
		   std::function<bool (const object_filter_config::filter_rule &rule)> on_match = nullptr,
		   bool* generic_match = NULL) const;

	// match() applies match_rule() to each of the rules in m_rules, stopping after
	// the first matching rule. It returns whether or not it matched an include rule
	// (or the result of the called on_match() callback, if defined)
	bool match(const sinsp_threadinfo *tinfo,
		   const sinsp_threadinfo *mtinfo,
	           const sinsp_container_info *container,
		   const infrastructure_state &is,
		   std::function<bool (const object_filter_config::filter_rule &rule)> on_match = nullptr,
		   bool* generic_match = NULL) const;

	// Calls callback function for all potential annotations
	// Used to make sure annotations will be available in infrastructure_state
	// Optionally pass custom rules to search for annotations
	void register_annotations(std::function<void (const std::string &str)> reg,
		std::vector<object_filter_config::filter_rule> *rules = nullptr) const;
#endif

protected:
	std::string m_context;
	bool m_enabled;
	std::vector<object_filter_config::filter_rule> m_rules;
};

class group_pctl_conf: public conf
{
	using base = conf;
	static const uint32_t default_check_interval_s = 60;
	static const uint32_t default_max_containers = 50;

public:
	explicit group_pctl_conf():
		base("Group Percentiles"),
		m_check_interval(default_check_interval_s),
		m_max_containers(default_max_containers)
	{}

	void set_check_interval(uint32_t val) { m_check_interval = val; }
	uint32_t check_interval() const { return m_check_interval; }
	static uint32_t check_interval_default() { return default_check_interval_s; }

	void set_max_containers(uint32_t val) { m_max_containers = val; }
	uint32_t max_containers() const { return m_max_containers; }
	static uint32_t max_containers_default() { return default_max_containers; }

#ifndef CYGWING_AGENT
	bool match(const sinsp_container_info *container, const infrastructure_state &is) const
	{
		return base::match(nullptr,
				   nullptr,
				   container,
				   is);
	}
#endif

private:
	uint32_t m_check_interval;
	uint32_t m_max_containers;
};
} // namespace proc_filter

#endif // _WIN32
