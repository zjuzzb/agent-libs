#pragma once
#ifndef _WIN32

#include <string>
#include <set>
#include <vector>
#include "sinsp.h"
#include "type_config.h"

// suppress depreacated warnings for auto_ptr in boost
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <yaml-cpp/yaml.h>
#pragma GCC diagnostic pop


namespace object_filter_config {

const std::string CONTAINER_LABEL = "container.label";
const std::string K8S_ANNOTATION = "kubernetes.pod.annotation";

const std::string* get_cont_label(const sinsp_container_info *container,
				  const std::string label);

std::vector<std::string> get_str_tokens(const std::string& str);

struct port_filter_rule {
        explicit port_filter_rule() : m_include(false), m_use_set(false),
                m_range_start(0), m_range_end(0) { }
	port_filter_rule(bool include,
			 bool use_set,
			 uint16_t range_start,
			 uint16_t range_end,
			 std::set<uint16_t>& port_set)
		: m_include(include),
		  m_use_set(use_set),
		  m_range_start(range_start),
		  m_range_end(range_end),
		  m_port_set(port_set)
	{
	}
        bool m_include;
        bool m_use_set; // Use set instead of range
        // Start and end are inclusive
        uint16_t m_range_start;
        uint16_t m_range_end;
        std::set<uint16_t> m_port_set;
};


bool portdef_to_pfrule(const std::string& str, port_filter_rule &pfr);
bool portdef_to_pfrule(const YAML::Node& node, port_filter_rule &pfr);

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

	filter_condition()
		: m_param_type(param_type::none),
		  m_param(""),
		  m_pattern(""),
		  m_port_match()
	{
	}
			       
	filter_condition(param_type type,
			 const std::string& param,
			 const std::string& pattern,
			 const std::vector<port_filter_rule>& port_match)
		: m_param_type(type),
		  m_param(param),
		  m_pattern(pattern),
		  m_port_match(port_match) {}

	param_type m_param_type;
	std::string m_param;
	std::string m_pattern;
	// Using port_filter_rules to implement port matching conditions
	// so we don't have to parse the pattern string every time
	std::vector<port_filter_rule> m_port_match;
};

struct rule_config {
	rule_config() {}
	rule_config(const std::string& port,
		    bool port_subst,
		    const std::string& path,
		    bool path_subst,
		    const std::map<std::string, std::string>& options,
		    bool options_subst,
		    const std::map<std::string, std::string>& tags,
		    bool tags_subst)	
		: m_port(port),
		  m_port_subst(port_subst),
		  m_path(path),
		  m_path_subst(path_subst),
		  m_options(options),
		  m_options_subst(options_subst),
		  m_tags(tags),
		  m_tags_subst(tags_subst)
	{
	}

	std::string m_port;
	bool m_port_subst;		// port contains {token(s)}
	std::string m_path;
	bool m_path_subst;		// path contains {token(s)}
	std::vector<port_filter_rule> m_port_rules;
	std::map<std::string,std::string> m_options;
	bool m_options_subst;	// one or more options contain {token(s)}
	std::map<std::string, std::string> m_tags;
	bool m_tags_subst; // one or more tags contain {tokens(s)}
};

struct filter_rule {
	explicit filter_rule() : m_include(false) { }
	filter_rule(std::string name,
		    bool include,
		    const std::vector<filter_condition>& cond,
		    const rule_config& config)
		: m_name(name),
		  m_include(include),
		  m_cond(cond),
		  m_config(config)
	{
	}

	std::string m_name;
	bool m_include;
	std::vector<filter_condition> m_cond;
	rule_config m_config;
};

class object_filter_config_data : public configuration_unit
{
public:
        /**
         * Our yaml interface has three levels of keys possible. If a given
         * value only requries fewer values, set the other strings to "". This
         * constructor should register this object with the configuration_manager
         * class.
         *
         * The value of this config is set to the default at construction, and
         * so will be valid, even if the yaml file has not been parsed yet.
         */
	object_filter_config_data(const std::string& description,
			     const std::string& key,
			     const std::string& subkey = "",
			     const std::string& subsubkey = "");

public: // stuff for configuration_unit
        std::string value_to_string() const override;
        void init(const yaml_configuration& raw_config) override;

public: // other stuff
        /**
         * Returns a const reference to the current value of this type_config.
         *
         * @return the value of this config
         */
        const std::vector<object_filter_config::filter_rule>& get() const;

private:
	std::vector<object_filter_config::filter_rule> m_data;
};
} // namespace object_filter_config

namespace YAML {
	template<>
	struct convert<object_filter_config::port_filter_rule> {
		static Node encode(const object_filter_config::port_filter_rule& rhs);
		static bool decode(const Node& node, object_filter_config::port_filter_rule& rhs);
	};
	template<>
	struct convert<object_filter_config::rule_config> {
		static Node encode(const object_filter_config::rule_config& rhs);
		static bool decode(const Node& node, object_filter_config::rule_config& rhs);
	};
	template<>
	struct convert<object_filter_config::filter_rule> {
		static Node encode(const object_filter_config::filter_rule& rhs);
		static bool decode(const Node& node, object_filter_config::filter_rule& rhs);
	};
}

#endif // _WIN32
