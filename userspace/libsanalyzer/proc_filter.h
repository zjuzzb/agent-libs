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
		tag
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
};

struct filter_rule {
	explicit filter_rule() : m_include(false) { }

	bool m_include;
	std::vector<filter_condition> m_cond;
	rule_config m_config;
};

class conf {
public:
	explicit conf(std::string context_str):
		m_context(std::move(context_str)),
		m_enabled(false),
		m_k8s_get_config(true)
	{}

	void set_enabled(bool val) { m_enabled = val; }
	bool enabled() const { return m_enabled; }

	void set_k8s_get_config(bool val) { m_k8s_get_config = val; }
	bool k8s_get_config() const { return m_k8s_get_config; }

	void set_rules(std::vector<filter_rule> rules) { m_rules = std::move(rules); }
	const std::vector<filter_rule>& rules() const { return m_rules; }

protected:
	bool match(const sinsp_threadinfo* tinfo, const sinsp_threadinfo* mtinfo,
	           const sinsp_container_info *container, infrastructure_state *is,
			   std::function<bool (const filter_rule &rule)> on_match = nullptr) const;

protected:
	std::string m_context;
	bool m_enabled;
	bool m_k8s_get_config;
	std::vector<filter_rule> m_rules;
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
