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
		{ K8S_ANN, k8s_annotation },
		{ "all", all },
		{ "always", all }
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

#ifndef CYGWING_AGENT
// Returns a boolean pair. The first indicates if the rule matched,
// the second if the rule should be applied
std::pair<bool, bool> conf::match_rule(const filter_rule &rule, int rule_num, const sinsp_threadinfo *tinfo,
		 const sinsp_threadinfo *mtinfo, const sinsp_container_info *container,
		 const infrastructure_state &infra_state,
		 std::function<bool (const filter_rule &rule)> on_match,
		 bool* generic_match) const

{
	std::pair<bool, bool> ret(false, false);

	bool dummy_generic_match; // dummy value so we don't need null checks everywhere
	if (!generic_match) {
		generic_match = &dummy_generic_match;
	}

	std::ostringstream reason;

	// A rule is considered matched if all of its conditions are met.
	// A rule is considered generic if all conditions of that rule are param_type::all
	bool matchrule = true;
	*generic_match = true;
	for (const auto& cond: rule.m_cond)
	{
		// in cases with multiple conditions, it's only generic
		// if there is only a single condition and it's all
		if (cond.m_param_type != filter_condition::param_type::all) {
			*generic_match = false;
		}

		// If a rule has multiple conditions, they must all be met.
		bool matchcond = true;
		switch(cond.m_param_type) {
		case filter_condition::param_type::all:
			// Catch all rule. Nothing to do
			reason << "all";
			break;
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
				if (!container) {
					matchcond = false;
					break;
				}
				infrastructure_state::uid_t c_uid = make_pair("container", container->m_id);

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
	ret.first = matchrule;

	if (matchrule) {
		if (tinfo != nullptr) {
			g_logger.format(sinsp_logger::SEV_DEBUG,
				"%s: Process with pid %d matches rule: %d: %s",
				m_context.c_str(), (int)tinfo->m_pid, rule_num, reason.str().c_str());
		} else if (container != nullptr) {
			g_logger.format(sinsp_logger::SEV_DEBUG,
				"%s: Container '%s' matches rule: %d: %s",
				m_context.c_str(), container->m_name.c_str(), rule_num, reason.str().c_str());
		}

		ret.second = on_match ? on_match(rule) : rule.m_include;
	}
	return ret;
}

bool conf::match(const sinsp_threadinfo *tinfo,
		 const sinsp_threadinfo *mtinfo,
		 const sinsp_container_info *container,
		 const infrastructure_state &infra_state,
		 std::function<bool (const filter_rule &rule)> on_match,
		 bool* generic_match) const

{
	if (!m_enabled)
	{
		return false;
	}

	int rule_num = 0;

	// Rough overview: There are rules, and each rule is comprised of conditions.
	// A rule is considered matched if all of its conditions are met.
	// The first rule which is matched breaks out of the loop, and no further
	// rules are considered.
	//
	// A rule is considered generic if all conditions of that rule are param_type::all
	for (const auto& rule: m_rules)
	{
		std::pair<bool, bool> matched = match_rule(rule, rule_num, tinfo, mtinfo,
			container, infra_state, on_match, generic_match);

		if (matched.first)
			return matched.second;
		rule_num++;
	}
	return false;
}

void conf::register_annotations(std::function<void (const std::string &)> reg,
	std::vector<filter_rule> *rules) const
{
	for (const auto& rule: rules ? *rules : m_rules)
	{
		for (const auto& cond: rule.m_cond)
		{
			if ((cond.m_param_type != filter_condition::param_type::k8s_annotation) &&
				(cond.m_param_type != filter_condition::param_type::tag))
				continue;

			reg(cond.m_param);
			g_logger.format(sinsp_logger::SEV_INFO,
				"%s: registering annotation %s", m_context.c_str(),
				cond.m_param.c_str());
		}
		if (rule.m_config.m_port_subst)
		{
			auto tokens = get_str_tokens(rule.m_config.m_port);
			for (const auto &token : tokens)
			{
				reg(token);
				g_logger.format(sinsp_logger::SEV_INFO,
					"%s: registering port annotation %s", m_context.c_str(),
					token.c_str());
			}
		}
		if (rule.m_config.m_path_subst)
		{
			auto tokens = get_str_tokens(rule.m_config.m_path);
			for (const auto &token : tokens)
			{
				reg(token);
				g_logger.format(sinsp_logger::SEV_INFO,
					"%s: registering path annotation %s", m_context.c_str(),
					token.c_str());
			}
		}
		if (rule.m_config.m_options_subst)
		{
			for (const auto &option : rule.m_config.m_options)
			{
				auto tokens = get_str_tokens(option.second);
				for (const auto &token : tokens)
				{
					reg(token);
					g_logger.format(sinsp_logger::SEV_INFO,
						"%s: registering option annotation %s", m_context.c_str(),
						token.c_str());
				}
			}
		}
		if (rule.m_config.m_tags_subst)
		{
			for (const auto &tag : rule.m_config.m_tags)
			{
				auto tokens = get_str_tokens(tag.second);
				for (const auto &token : tokens)
				{
					reg(token);
					g_logger.format(sinsp_logger::SEV_INFO,
						"%s: registering tag annotation %s", m_context.c_str(),
						token.c_str());
				}
			}
		}
	}
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
		rule.m_name = rule_it->first.as<string>();
		rule.m_include = (rule.m_name == "include");

		if (rule_it->second.IsScalar())
		{
			proc_filter::filter_condition cond;
			cond.m_param = rule_it->second.as<string>();

			cond.m_param_type = proc_filter::filter_condition::param2type(cond.m_param);
			if (cond.m_param_type == proc_filter::filter_condition::param_type::all)
			{
				// "all" is the only condition that doesn't require a value
				// In this shape it can't be combined with other conditions
				// or with a specific config for the rule
				rule.m_cond.emplace_back(cond);
				rhs = rule;
				return true;
			}
			else if (cond.m_param_type != proc_filter::filter_condition::param_type::none)
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
