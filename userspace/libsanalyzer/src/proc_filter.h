#pragma once
#ifndef _WIN32

#include <string>
#include <set>
#include <vector>

// suppress depreacated warnings for auto_ptr in boost
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <yaml-cpp/yaml.h>
#pragma GCC diagnostic pop


class sinsp_container_info;
class infrastructure_state;
class sinsp_threadinfo;

namespace proc_filter {

const std::string CONT_LABEL("container.label");
const std::string K8S_ANN("kubernetes.pod.annotation");

const std::string* get_cont_label(const sinsp_container_info *container,
		const std::string label);

struct port_filter_rule {
	explicit port_filter_rule() : m_include(false), m_use_set(false),
		m_range_start(0), m_range_end(0) { }
	bool m_include;
	bool m_use_set; // Use set instead of range
	// Start and end are inclusive
	uint16_t m_range_start;
	uint16_t m_range_end;
	std::set<uint16_t> m_port_set;
};

bool portdef_to_pfrule(const std::string& str, port_filter_rule &pfr);
bool portdef_to_pfrule(const YAML::Node& node, port_filter_rule &pfr);
std::set<uint16_t> filter_ports(const std::set<uint16_t>& ports,
	const std::vector<port_filter_rule>& rules);

struct filter_condition {
	enum param_type {
		none,
		port,
		container_image,
		container_name,
		container_label,
		process_name,
		process_cmdline,
		app_check_match,
		k8s_annotation,	// obsolete, to be replaced with generic tag
		tag,
		all				// Match all
	};
	static param_type param2type(std::string);

	param_type m_param_type;
	std::string m_param;
	std::string m_pattern;
	// Using port_filter_rules to implement port matching conditions
	// so we don't have to parse the pattern string every time
	std::vector<port_filter_rule> m_port_match;
};

struct rule_config {
	std::string m_port;
	bool m_port_subst;		// port contains {token(s)}
	std::string m_path;
	bool m_path_subst;		// path contains {token(s)}
	std::vector<port_filter_rule> m_port_rules;
	std::map<std::string,std::string> m_options;
	bool m_options_subst;	// one or more options contain {token(s)}
	std::map<std::string,std::string> m_tags;
	bool m_tags_subst;		// one or more tags contain {token(s)}
};

struct filter_rule {
	explicit filter_rule() : m_include(false) { }

	std::string m_name;
	bool m_include;		// whether or not m_name == "include"
	std::vector<filter_condition> m_cond;
	rule_config m_config;
};

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

	void set_rules(std::vector<filter_rule> rules) { m_rules = std::move(rules); }
	const std::vector<filter_rule>& rules() const { return m_rules; }

#ifndef CYGWING_AGENT
	// match_rule() returns a boolean pair. The first indicates if the rule matched,
	// the second is the result of on_match(), if passed in, or m_include otherwise.
	std::pair<bool, bool> match_rule(const filter_rule &rule, int rule_num,
		   const sinsp_threadinfo *tinfo,
		   const sinsp_threadinfo *mtinfo,
	           const sinsp_container_info *container,
		   const infrastructure_state &is,
		   std::function<bool (const filter_rule &rule)> on_match = nullptr,
		   bool* generic_match = NULL) const;

	// match() applies match_rule() to each of the rules in m_rules, stopping after
	// the first matching rule. It returns whether or not it matched an include rule
	// (or the result of the called on_match() callback, if defined)
	bool match(const sinsp_threadinfo *tinfo,
		   const sinsp_threadinfo *mtinfo,
	           const sinsp_container_info *container,
		   const infrastructure_state &is,
		   std::function<bool (const filter_rule &rule)> on_match = nullptr,
		   bool* generic_match = NULL) const;

	// Calls callback function for all potential annotations
	// Used to make sure annotations will be available in infrastructure_state
	// Optionally pass custom rules to search for annotations
	void register_annotations(std::function<void (const std::string &str)> reg,
		std::vector<filter_rule> *rules = nullptr) const;
#endif

protected:
	std::string m_context;
	bool m_enabled;
	std::vector<filter_rule> m_rules;
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

namespace YAML {
	template<>
	struct convert<proc_filter::port_filter_rule> {
		static Node encode(const proc_filter::port_filter_rule& rhs);
		static bool decode(const Node& node, proc_filter::port_filter_rule& rhs);
	};
	template<>
	struct convert<proc_filter::rule_config> {
		static Node encode(const proc_filter::rule_config& rhs);
		static bool decode(const Node& node, proc_filter::rule_config& rhs);
	};
	template<>
	struct convert<proc_filter::filter_rule> {
		static Node encode(const proc_filter::filter_rule& rhs);
		static bool decode(const Node& node, proc_filter::filter_rule& rhs);
	};
}

#endif // _WIN32
