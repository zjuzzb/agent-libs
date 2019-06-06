#include "object_filter.h"
#include "object_filter_config.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_int.h"
#include "analyzer_thread.h"
#include "infrastructure_state.h"
#include <utils.h>
#include <sstream>

namespace {

template<typename T>
vector<T> get_sequence(YAML::Node node)
{
	vector<T> ret;
	for(const auto& item : node)
	{
		ret.push_back(item.as<T>());
	}
	return ret;
}

bool contains_token(const string &str)
{
	auto bo = str.find('{');
	if (bo == string::npos)
		return false;
	auto bc = str.find('}');
	if (bc == string::npos)
		return false;
	return (bc > bo);
}

}

namespace object_filter_config {

bool portdef_to_pfrule(const string& str, port_filter_rule& out_rule)
{
	port_filter_rule rule;

	// Parse single port or range
	rule.m_use_set = false;
	auto delim = str.find("-");
	rule.m_range_start = atoi(str.substr(0, delim).c_str());
	rule.m_range_end = (delim == string::npos) ? rule.m_range_start :
		atoi(str.substr(delim + 1, string::npos).c_str());
	out_rule = rule;

	return true;
}

bool portdef_to_pfrule(const YAML::Node& node, port_filter_rule& out_rule)
{
	if (node.IsSequence())
	{
		port_filter_rule rule;

		rule.m_use_set = true;
		for (const auto& port_node : node)
		{
			if (!port_node.IsScalar())
				continue;

			uint16_t p = port_node.as<uint16_t>();
			if (p) {
				rule.m_port_set.insert(p);
			}
		}
		out_rule = rule;
		return true;
	}
	else if (node.IsScalar())
	{
		return portdef_to_pfrule(node.as<string>(), out_rule);
	}

	return false;
}

filter_condition::param_type
filter_condition::param2type(std::string pstr)
{
	static const map<std::string, param_type> param_map =
	{
		{ "port", port },
		{ "container.image", container_image },
		{ "container.name", container_name },
		{ CONTAINER_LABEL, container_label },
		{ "process.name", process_name },
		{ "process.cmdline", process_cmdline },
		{ "appcheck.match", app_check_match },
		{ K8S_ANNOTATION, k8s_annotation },
		{ "all", all },
		{ "always", all }
	};

	auto it = param_map.find(pstr);
	if (it != param_map.end())
		return(it->second);

	if (!pstr.compare(0, CONTAINER_LABEL.size(), CONTAINER_LABEL))
		return container_label;

	if (!pstr.compare(0, K8S_ANNOTATION.size(), K8S_ANNOTATION))
		return k8s_annotation;

	// Everything else is assumed to be an infrastructure tag (unless empty)
	if (!pstr.empty())
		return param_type::tag;

	return param_type::none;
}

std::vector<std::string> get_str_tokens(const std::string &str)
{
	vector<string> ret;

	size_t lpos = 0;
	size_t pos;
	while ((pos = str.find('{', lpos)) != string::npos)
	{
		size_t bc = str.find('}', pos);
		if (bc == string::npos)
		{
			return ret;
		}
		string token = str.substr(pos+1, bc-(pos+1));
		ret.emplace_back(move(token));
		lpos = bc + 1;
	}
	return ret;
}

const string* get_cont_label(const sinsp_container_info *container, const string label)
{
        if (!container)
                return nullptr;
        const auto& it = container->m_labels.find(label);
        if (it == container->m_labels.end())
                return nullptr;
        return &(it->second);
}

object_filter_config_data::object_filter_config_data(const std::string& description,
						     const std::string& key,
						     const std::string& subkey,
						     const std::string& subsubkey)
	: configuration_unit(key, subkey, subsubkey, description),
	  m_data()
{
	hidden(true);
}

std::string object_filter_config_data::value_to_string() const
{
	return "";
}

void object_filter_config_data::init(const yaml_configuration& raw_config)
{
	if (get_subkey().empty())
        {
                m_data = raw_config.get_first_deep_sequence<std::vector<object_filter_config::filter_rule>>(get_key());
        }
        else if (get_subsubkey().empty())
        {
                m_data = raw_config.get_first_deep_sequence<std::vector<object_filter_config::filter_rule>>(get_key(),
												get_subkey());
        }
        else
        {
                m_data = raw_config.get_first_deep_sequence<std::vector<object_filter_config::filter_rule>>(get_key(),
												get_subkey(),
												get_subsubkey());
        }
}

const std::vector<object_filter_config::filter_rule>& object_filter_config_data::get() const
{
	return m_data;
}

} // namespace object_filter_config

namespace YAML {

bool convert<object_filter_config::port_filter_rule>::decode(const Node &node,
		object_filter_config::port_filter_rule &rhs)
{
	if (!node.IsMap())
		return false;

	// This decoder gets called for every port-filter rule
	for (auto rule_it = node.begin();
		rule_it != node.end(); rule_it++)
	{
		if (!rule_it->first.IsScalar())
		{
			continue;
		}
		object_filter_config::port_filter_rule rule;
		if (object_filter_config::portdef_to_pfrule(rule_it->second, rule))
		{
			rule.m_include = (rule_it->first.as<string>() == "include");
			rhs = rule;
			return true;
		}
	}
	return false;
}

bool convert<object_filter_config::rule_config>::decode(const Node &node,
		object_filter_config::rule_config &rhs)
{
	if (!node.IsMap())
		return false;
        rhs.m_options_subst = false;
        rhs.m_tags_subst = false;

        for (auto conf_line = node.begin();
                conf_line != node.end(); conf_line++)
        {
                if (!conf_line->first.IsScalar())
                {
                        continue;
                }
                if ((conf_line->first.as<string>() == "port_filter") &&
                        conf_line->second.IsSequence())
                {
                        rhs.m_port_rules = get_sequence<object_filter_config::port_filter_rule>(conf_line->second);
                }
                else if (conf_line->first.as<string>() == "path")
                {
                        // If the path is defined as {path} without parentheses it is
                        // interpreted by yaml as a map. We just try
                        // to turn it back into a string for parsing
                        if (conf_line->second.IsMap())
                        {
                                for (auto m : conf_line->second)
                                {
                                        if (!m.first.IsScalar())
                                                continue;
                                        rhs.m_path= "{" + m.first.as<string>() + "}";
                                        break;
                                }
                        }
                        else if (conf_line->second.IsScalar())
                        {
                                rhs.m_path = conf_line->second.as<string>();
                        }
                        else
                        {
                                continue;
                        }
                        rhs.m_path_subst = contains_token(rhs.m_path);
                }
                else if (conf_line->first.as<string>() == "port")
                {
                        // If the port is defined as {port} without parentheses it is
                        // interpreted by yaml as a map. We just try
                        // to turn it back into a string for parsing
                        if (conf_line->second.IsMap())
                        {
                                for (auto m : conf_line->second)
                                {
                                        if (!m.first.IsScalar())
                                                continue;
                                        rhs.m_port= "{" + m.first.as<string>() + "}";
                                        break;
                                }
                        }
                        else if (conf_line->second.IsScalar())
                        {
                                rhs.m_port = conf_line->second.as<string>();
                        }
                        else
                        {
                                continue;
                        }
                        rhs.m_port_subst = contains_token(rhs.m_port);
                }
		else if (conf_line->first.as<string>() == "tags")
                {
                        // Should be a map
                        g_logger.format(sinsp_logger::SEV_DEBUG,
                                "Tags type: %d", conf_line->second.Type());
                        if (conf_line->second.IsMap())
                        {
                                for (auto m : conf_line->second)
                                {
                                        g_logger.format(sinsp_logger::SEV_DEBUG,
                                                "Tags item type 1: %d, type 2: %d", m.first.Type(), m.second.Type());
                                        if (!m.first.IsScalar())
                                                continue;
                                        string value;
                                        if (m.second.IsMap())
                                        {
                                                for (auto it : conf_line->second)
                                                {
                                                        if (!it.first.IsScalar())
                                                                continue;
                                                        value = "{" + it.first.as<string>() + "}";
                                                        break;
                                                }
                                        }
                                        else if (m.second.IsScalar())
                                        {
                                                value = m.second.as<string>();
                                        }
                                        else
                                        {
                                                continue;
                                        }
                                        rhs.m_tags_subst |= contains_token(value);
                                        rhs.m_tags[m.first.as<string>()] = move(value);
                                }
                        }
                }
                else if (conf_line->second.IsScalar())
                {
                        // Allow arbitrary string config options to pass to sdchecks
                        string value = conf_line->second.as<string>();
                        rhs.m_options_subst |= contains_token(value);
                        rhs.m_options[conf_line->first.as<string>()] = move(value);
                }
        }
        return true;

}

bool convert<object_filter_config::filter_rule>::decode(const Node &node,
		object_filter_config::filter_rule &rhs)
{
	if (!node.IsMap())
		return false;

	for (auto rule_it = node.begin();
	     rule_it != node.end(); rule_it++)
	{
		if (!rule_it->first.IsScalar())
		{
			continue;
		}

		object_filter_config::filter_rule rule;
		rule.m_name = rule_it->first.as<string>();
		rule.m_include = (rule.m_name == "include");

		if (rule_it->second.IsScalar())
		{
			object_filter_config::filter_condition cond;
                        cond.m_param = rule_it->second.as<string>();

                        cond.m_param_type = object_filter_config::filter_condition::param2type(cond.m_param);
                        if (cond.m_param_type == object_filter_config::filter_condition::param_type::all)
                        {
                                // "all" is the only condition that doesn't require a value
                                // In this shape it can't be combined with other conditions
                                // or with a specific config for the rule
                                rule.m_cond.emplace_back(cond);
                                rhs = rule;
                                return true;
                        }
                        else if (cond.m_param_type != object_filter_config::filter_condition::param_type::none)
                        {
                                g_logger.format(sinsp_logger::SEV_WARNING,
                                        "Rule condition %s requires comparison value",
                                        cond.m_param.c_str());
                        }
                }
                if (!rule_it->second.IsMap())
                        continue; // The rule conditions should be in map form

                for (auto cond_it = rule_it->second.begin();
                        cond_it != rule_it->second.end(); cond_it++)
                {
                        if (!cond_it->first.IsScalar())
                                continue;

                        if (cond_it->first.as<string>() == "conf") {
                                rule.m_config = cond_it->second.as<object_filter_config::rule_config>();
                                continue;
                        }

                        object_filter_config::filter_condition cond;
                        cond.m_param = cond_it->first.as<string>();
                        if (cond.m_param.empty())
                                continue;

                        using pf_flt_cond = object_filter_config::filter_condition;
                        cond.m_param_type = pf_flt_cond::param2type(cond.m_param);
                        if (cond.m_param_type == pf_flt_cond::param_type::container_label)
                        {
                                // strip "container.label" from param
                                cond.m_param = cond.m_param.substr(object_filter_config::CONTAINER_LABEL.size()+1);
                        }
                        if (cond.m_param_type == pf_flt_cond::param_type::port)
                        {
                                // Create port_filter_rule to do port matches without
                                // having to reparse the string
                                object_filter_config::port_filter_rule pfr;
                                object_filter_config::portdef_to_pfrule(cond_it->second, pfr);
                                pfr.m_include = true;
                                cond.m_port_match.push_back(pfr);
                        }
                        if (cond_it->second.IsScalar())
                        {
                                cond.m_pattern = cond_it->second.as<string>();
                        }
                        rule.m_cond.emplace_back(cond);
                }
                if (!rule.m_cond.empty())
                {
                        rhs = rule;
                        return true;
                }
        }
        return false;
}

} // namespace YAML
