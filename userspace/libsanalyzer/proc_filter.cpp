#include <fnmatch.h>
#include "proc_filter.h"
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

namespace proc_filter{

// infrastructure state doesn't seem to be storing docker container labels
// (except ones passed by orchestrators) so keeping this around for now
const string* get_cont_label(const sinsp_container_info *container, const string label)
{
	if (!container)
		return nullptr;
	const auto& it = container->m_labels.find(label);
	if (it == container->m_labels.end())
		return nullptr;
	return &(it->second);
}

set<uint16_t> filter_ports(const set<uint16_t>& sports,
		const vector<port_filter_rule>& rules)
{
	set<uint16_t> start_ports = sports;
	set<uint16_t> filtered_ports;

	for (const auto& portrule: rules)
	{
		if (start_ports.empty())
			break;
		set<uint16_t> matched_ports;
		for (const auto& port : start_ports)
		{
			if (portrule.m_use_set) {
				if (portrule.m_port_set.find(port) != portrule.m_port_set.end())
				{
					matched_ports.insert(port);
				}
			} else {
				if ((port >= portrule.m_range_start) &&
					(port <= portrule.m_range_end))
				{
					matched_ports.insert(port);
				}
			}
		}
		if (!matched_ports.empty())
		{
			if (portrule.m_include)
			{
				filtered_ports.insert(matched_ports.begin(), matched_ports.end());
			}
			else
			{
				for (const auto &p : matched_ports)
				{
					start_ports.erase(p);
				}
			}
		}
	}

	return filtered_ports;
}

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
		{ CONT_LABEL, container_label },
		{ "process.name", process_name },
		{ "process.cmdline", process_cmdline },
		{ "appcheck.match", app_check_match },
		{ K8S_ANN, k8s_annotation }
	};

	auto it = param_map.find(pstr);
	if (it != param_map.end())
		return(it->second);

	if (!pstr.compare(0, CONT_LABEL.size(), CONT_LABEL))
		return container_label;

	if (!pstr.compare(0, K8S_ANN.size(), K8S_ANN))
		return k8s_annotation;

	// Everything else is assumed to be an infrastructure tag (unless empty)
	if (!pstr.empty())
		return param_type::tag;

	return param_type::none;
}

#ifndef CYGWING_AGENT
bool conf::match(const sinsp_threadinfo *tinfo, const sinsp_threadinfo *mtinfo,
	const sinsp_container_info *container, const infrastructure_state &infra_state,
	std::function<bool (const filter_rule &rule)> on_match) const
{
	if (!m_enabled)
		return false;

	infrastructure_state::uid_t c_uid;
	if (container)
	{
		c_uid = make_pair("container", container->m_id);
	}

	std::ostringstream reason;
	int rn = 0;

	for (const auto& rule: m_rules)
	{
		bool matchrule = true;
		for (const auto& cond: rule.m_cond)
		{
			// If a rule has multiple conditions, they must all be met.
			bool matchcond = true;
			switch(cond.m_param_type) {
			case filter_condition::param_type::port:
			{
				if (tinfo == nullptr) {
					matchcond = false;
					break;
				}

				auto start_ports = tinfo->m_ainfo->listening_ports();
				auto ports = filter_ports(start_ports, cond.m_port_match);
				if (!ports.empty()) {
					reason << ports.size() << " ports match: " << *(ports.begin());
				} else {
					matchcond = false;
				}

				break;
			}
			case filter_condition::param_type::process_name:
				if (tinfo == nullptr) {
					matchcond = false;
					break;
				}
				matchcond = !fnmatch(cond.m_pattern.c_str(), tinfo->m_comm.c_str(), FNM_EXTMATCH);
				if (matchcond) {
					reason << "procname = " << cond.m_pattern;
				}
				break;
			case filter_condition::param_type::process_cmdline:
			{
				if (tinfo == nullptr) {
					matchcond = false;
					break;
				}

				// Should this match include exe and arguments?
				if ((tinfo->m_exe.find(cond.m_pattern) == string::npos) &&
					find_if(tinfo->m_args.begin(), tinfo->m_args.end(),
							[&cond](const string& arg)
							{
								return !fnmatch(cond.m_pattern.c_str(),
											arg.c_str(), FNM_EXTMATCH);
							}) == tinfo->m_args.end())
				{
					matchcond = false;
				}
				if (matchcond) {
					reason << "arg found: " << cond.m_pattern;
				}

				break;
			}
			case filter_condition::param_type::container_name:
				if (!container) {
					matchcond = false;
					break;
				}
				matchcond = !fnmatch(cond.m_pattern.c_str(), container->m_name.c_str(), FNM_EXTMATCH);
				if (matchcond) {
					reason << "container.name = " << container->m_name;
				}
				break;
			case filter_condition::param_type::container_image:
				if (!container) {
					matchcond = false;
					break;
				}
				matchcond = !fnmatch(cond.m_pattern.c_str(), container->m_image.c_str(), FNM_EXTMATCH);
				if (matchcond) {
					reason << "container.image = " << container->m_image;
				}
				break;
			case filter_condition::param_type::container_label:
			{
				const string *lbl = get_cont_label(container, cond.m_param);
				if(!lbl || fnmatch(cond.m_pattern.c_str(),
					lbl->c_str(), FNM_EXTMATCH))
				{
					matchcond = false;
					break;
				}
				matchcond = true;
				reason << "container.label." << cond.m_param << " = " << *lbl;
				break;
			}
			case filter_condition::param_type::k8s_annotation:
			case filter_condition::param_type::tag:
			{
				string val;
				bool found = infra_state.find_tag(c_uid, cond.m_param, val);
				if(!found || fnmatch(cond.m_pattern.c_str(),
					val.c_str(), FNM_EXTMATCH))
				{
					matchcond = false;
					break;
				}
				matchcond = true;
				reason << cond.m_param << " = " << val;
				break;
			}
			case filter_condition::param_type::app_check_match:
				if (mtinfo == nullptr) {
					matchcond = false;
					break;
				}

				matchcond = mtinfo->m_ainfo->found_app_check_by_fnmatch(cond.m_pattern);
				if (matchcond) {
					reason << "app_check found for " << cond.m_pattern;
				}
				break;
			default:
				g_logger.format(sinsp_logger::SEV_INFO,
					"%s: Condition for param_type %d not yet implemented",
					m_context.c_str(), cond.m_param_type);
				matchcond = false;
				break;
			}
			if (!matchcond) {
				matchrule = false;
				break;
			}
		}
		if (matchrule) {
			if (tinfo != nullptr) {
				g_logger.format(sinsp_logger::SEV_DEBUG,
					"%s: Process with pid %d matches rule: %d: %s",
					m_context.c_str(), (int)tinfo->m_pid, rn, reason.str().c_str());
			} else if (container != nullptr) {
				g_logger.format(sinsp_logger::SEV_DEBUG,
					"%s: Container '%s' matches rule: %d: %s",
					m_context.c_str(), container->m_name.c_str(), rn, reason.str().c_str());
			}

			auto ret = rule.m_include;
			if (on_match) {
				ret = on_match(rule);
			}
			return ret;
		}
		rn++;
	}
	return false;
}
#endif // CYGWING_AGENT

} // namespace proc_filter

namespace YAML {

bool convert<proc_filter::port_filter_rule>::decode(const Node &node,
		proc_filter::port_filter_rule &rhs)
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
		proc_filter::port_filter_rule rule;
		if (proc_filter::portdef_to_pfrule(rule_it->second, rule))
		{
			rule.m_include = (rule_it->first.as<string>() == "include");
			rhs = rule;
			return true;
		}
	}
	return false;
}

bool convert<proc_filter::rule_config>::decode(const Node &node,
		proc_filter::rule_config &rhs)
{
	if (!node.IsMap())
		return false;

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
			rhs.m_port_rules = get_sequence<proc_filter::port_filter_rule>(conf_line->second);
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
			rhs.m_port_subst = contains_token(rhs.m_port);
		}
	}
	return true;
}

bool convert<proc_filter::filter_rule>::decode(const Node &node,
		proc_filter::filter_rule &rhs)
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
		proc_filter::filter_rule rule;
		rule.m_include = (rule_it->first.as<string>() == "include");

		if (!rule_it->second.IsMap())
			continue; // The rule conditions should be in map form

		for (auto cond_it = rule_it->second.begin();
			cond_it != rule_it->second.end(); cond_it++)
		{
			if (!cond_it->first.IsScalar())
				continue;

			if (cond_it->first.as<string>() == "conf") {
				rule.m_config = cond_it->second.as<proc_filter::rule_config>();
				continue;
			}

			proc_filter::filter_condition cond;
			cond.m_param = cond_it->first.as<string>();
			if (cond.m_param.empty())
				continue;

			using pf_flt_cond = proc_filter::filter_condition;
			cond.m_param_type = pf_flt_cond::param2type(cond.m_param);
			if (cond.m_param_type == pf_flt_cond::param_type::container_label)
			{
				// strip "container.label" from param
				cond.m_param = cond.m_param.substr(proc_filter::CONT_LABEL.size()+1);
			}
			if (cond.m_param_type == pf_flt_cond::param_type::port)
			{
				// Create port_filter_rule to do port matches without
				// having to reparse the string
				proc_filter::port_filter_rule pfr;
				proc_filter::portdef_to_pfrule(cond_it->second, pfr);
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
