#include <fnmatch.h>
// #include "../dragent/configuration.h"
#include "prometheus.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_int.h"
#include "analyzer_thread.h"
#include "infrastructure_state.h"
#include <utils.h>

static const std::string cont_label_str = "container.label";
static const std::string k8s_ann_str = "kubernetes.pod.annotation";

// infrastructure state doesn't seem to be storing docker container labels
// (except ones passed by orchestrators) so keeping this around for now
static const string* get_cont_label(const sinsp_container_info *container, const string label)
{
	if (!container)
		return nullptr;
	const auto& it = container->m_labels.find(label);
	if (it == container->m_labels.end())
		return nullptr;
	return &(it->second);
}

static string replace_tokens(const string src, const sinsp_container_info *container, infrastructure_state *infra_state, infrastructure_state::uid_t c_uid)
{
	string ret;
	size_t lpos = 0;
	size_t pos;
	while ((pos = src.find('{', lpos)) != string::npos)
	{
		if (pos > lpos)
			ret += src.substr(lpos, pos-lpos);

		size_t bc = src.find('}', pos);
		if (bc == string::npos)
		{
			lpos = pos+1;
			break;
		}
		string token = src.substr(pos+1, bc-(pos+1));
		if (!token.compare(0, cont_label_str.size(), cont_label_str))
		{
			const string *strptr = get_cont_label(container,
				token.substr(cont_label_str.size()+1, string::npos));
			if (strptr)
			{
				ret += *strptr;
			}
		}
		else
		{
			string value;
			bool found = infra_state->find_tag(c_uid, token, value);
			if (found)
			{
				ret += value;
			}
		}
		lpos = bc + 1;
	}
	ret += src.substr(lpos, string::npos);
	return ret;
}

set<uint16_t> prometheus_conf::filter_ports(const set<uint16_t>& sports,
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

bool prometheus_conf::portdef_to_pfrule(const string& str, port_filter_rule& out_rule)
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

bool prometheus_conf::portdef_to_pfrule(const YAML::Node& node, port_filter_rule& out_rule)
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

bool prometheus_conf::match(const sinsp_threadinfo *tinfo, const sinsp_threadinfo *mtinfo, const sinsp_container_info *container, infrastructure_state *infra_state, set<uint16_t> &out_ports, string &out_path) const
{
	if (!m_enabled)
		return false;
	auto start_ports = tinfo->m_ainfo->listening_ports();

	infrastructure_state::uid_t c_uid;
	if (container)
	{
		c_uid = make_pair("container", container->m_id);
	}

	char reason[256];
	memset(reason, 0, 256);
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
				auto ports = filter_ports(start_ports, cond.m_port_match);
				if (!ports.empty())
				{
					snprintf(reason, sizeof(reason), "%d ports match: %d", 
						(int)ports.size(), (int)*(ports.begin()));
				}
				else
					matchcond = false;

				break;
			}
			case filter_condition::param_type::process_name:
				matchcond = !fnmatch(cond.m_pattern.c_str(), tinfo->m_comm.c_str(), FNM_EXTMATCH);
				if (matchcond)
					snprintf(reason, sizeof(reason), "procname = %s", cond.m_pattern.c_str());
				break;
			case filter_condition::param_type::process_cmdline:
			{
				// Should this match include exe and arguments?
				if ((tinfo->m_exe.find(cond.m_pattern) == string::npos) &&
					find_if(tinfo->m_args.begin(), tinfo->m_args.end(), [&cond](const string& arg)
					{
						return !fnmatch(cond.m_pattern.c_str(), arg.c_str(), FNM_EXTMATCH);
					}) == tinfo->m_args.end())
				{
					matchcond = false;
				}
				if (matchcond)
					snprintf(reason, sizeof(reason), "arg found: %s", cond.m_pattern.c_str());

				break;
			}
			case filter_condition::param_type::container_name:
				if (!container) {
					matchcond = false;
					break;
				}
				matchcond = !fnmatch(cond.m_pattern.c_str(), container->m_name.c_str(), FNM_EXTMATCH);
				if (matchcond)
					snprintf(reason, sizeof(reason), "container.name = %s", container->m_name.c_str());
				break;
			case filter_condition::param_type::container_image:
				if (!container) {
					matchcond = false;
					break;
				}
				matchcond = !fnmatch(cond.m_pattern.c_str(), container->m_image.c_str(), FNM_EXTMATCH);
				if (matchcond)
					snprintf(reason, sizeof(reason), "container.image = %s", container->m_image.c_str());
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
				snprintf(reason, sizeof(reason), "container.label.%s = %s",
					cond.m_param.c_str(), lbl->c_str());
				break;
			}
			case filter_condition::param_type::k8s_annotation:
			case filter_condition::param_type::tag:
			{
				string val;
				bool found = infra_state->find_tag(c_uid, cond.m_param, val);
				if(!found || fnmatch(cond.m_pattern.c_str(),
					val.c_str(), FNM_EXTMATCH))
				{
					matchcond = false;
					break;
				}
				matchcond = true;
				snprintf(reason, sizeof(reason), "%s = %s",
					cond.m_param.c_str(), val.c_str());
				break;
			}
			case filter_condition::param_type::app_check_match:
				matchcond = mtinfo->m_ainfo->found_app_check_by_fnmatch(cond.m_pattern);
				if (matchcond)
					snprintf(reason, sizeof(reason), "app_check found for %s", cond.m_pattern.c_str());
				break;
			default:
				g_logger.format(sinsp_logger::SEV_INFO, 
					"Condition for param_type %d not yet implemented",
					cond.m_param_type);
				matchcond = false;
				break;
			}
			if (!matchcond) {
				matchrule = false;
				break;
			}
		}
		if (matchrule) {
			g_logger.format(sinsp_logger::SEV_DEBUG,
				"Process %d matches prometheus rule: %d: %s",
				(int)tinfo->m_pid, rn, reason);
			if (rule.m_include) {
				out_ports = start_ports;
				if (!rule.m_config.m_port.empty())
				{
					out_ports.clear();
					string pstr = rule.m_config.m_port_subst ? replace_tokens(rule.m_config.m_port, container, infra_state, c_uid) : rule.m_config.m_port;
					uint16_t p = atoi(pstr.c_str());
					// If port is non-null we assume only that port should be
					// scanned, so a mismatch means we don't scan.
					// If the port is 0 (because a token couldn't be resolved
					// or otherwise) we can still try using a port-filter.
					if (p && (start_ports.find(p) != start_ports.end()))
					{
						g_logger.format(sinsp_logger::SEV_DEBUG,
							"Process %d set port to : %d",
							(int)tinfo->m_pid, (int)p);
						out_ports.emplace(p);
					}
					else if (p)
					{
						// port is non-null but not found -> skip scan.
						return false;
					}
				}
				// If we found a matching configured port we skip
				// the port-filter
				if (!rule.m_config.m_port_rules.empty() && (rule.m_config.m_port.empty() || out_ports.empty()))
				{
					out_ports = filter_ports(start_ports, rule.m_config.m_port_rules);
				}
				if (out_ports.empty()) {
					return false;
				}
				if (!rule.m_config.m_path.empty())
				{
					out_path = rule.m_config.m_path_subst ? replace_tokens(rule.m_config.m_path, container, infra_state, c_uid) : rule.m_config.m_path;
				}
			}
			return rule.m_include;
		}
		rn++;
	}
	return false;
}

prometheus_conf::filter_condition::param_type 
prometheus_conf::filter_condition::param2type(std::string pstr)
{
	static const map<std::string, param_type> param_map =
	{
		{ "port", port },
		{ "container.image", container_image },
		{ "container.name", container_name },
		{ cont_label_str, container_label },
		{ "process.name", process_name },
		{ "process.cmdline", process_cmdline },
		{ "appcheck.match", app_check_match },
		{ k8s_ann_str, k8s_annotation }
	};

	auto it = param_map.find(pstr);
	if (it != param_map.end())
		return(it->second);
	
	if (!pstr.compare(0, cont_label_str.size(), cont_label_str))
		return container_label;

	if (!pstr.compare(0, k8s_ann_str.size(), k8s_ann_str))
		return k8s_annotation;

	// Everything else is assumed to be an infrastructure tag (unless empty)
	if (!pstr.empty())
		return param_type::tag;

	return param_type::none;
}

template<typename T>
static vector<T> get_sequence(YAML::Node node)
{
	vector<T> ret;
	for(const auto& item : node)
	{
		ret.push_back(item.as<T>());
	}
	return ret;
}

static bool contains_token(const string &str)
{
	auto bo = str.find('{');
	if (bo == string::npos)
		return false;
	auto bc = str.find('}');
	if (bc == string::npos)
		return false;
	return (bc > bo);
}

bool YAML::convert<prometheus_conf::port_filter_rule>::decode(const YAML::Node &node, prometheus_conf::port_filter_rule &rhs)
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
		prometheus_conf::port_filter_rule rule;
		if (prometheus_conf::portdef_to_pfrule(rule_it->second, rule))
		{
			rule.m_include = (rule_it->first.as<string>() == "include");
			rhs = rule;
			return true;
		}
	}
	return false;
}

bool YAML::convert<prometheus_conf::rule_config>::decode(const YAML::Node &node, prometheus_conf::rule_config &rhs)
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
			rhs.m_port_rules = get_sequence<prometheus_conf::port_filter_rule>(conf_line->second);
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

bool YAML::convert<prometheus_conf::filter_rule>::decode(const YAML::Node &node, prometheus_conf::filter_rule &rhs)
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
		prometheus_conf::filter_rule rule;
		rule.m_include = (rule_it->first.as<string>() == "include");

		if (!rule_it->second.IsMap())
			continue; // The rule conditions should be in map form

		for (auto cond_it = rule_it->second.begin();
			cond_it != rule_it->second.end(); cond_it++)
		{
			if (!cond_it->first.IsScalar())
				continue;

			if (cond_it->first.as<string>() == "conf") {
				rule.m_config = cond_it->second.as<prometheus_conf::rule_config>();
				continue;
			}

			prometheus_conf::filter_condition cond;
			cond.m_param = cond_it->first.as<string>();
			if (cond.m_param.empty())
				continue;

			cond.m_param_type = prometheus_conf::filter_condition::param2type(cond.m_param);
			if (cond.m_param_type == prometheus_conf::filter_condition::
				param_type::container_label)
			{
				// strip "container.label" from param
				cond.m_param = cond.m_param.substr(cont_label_str.size()+1);
			}
			if (cond.m_param_type == prometheus_conf::filter_condition::param_type::port)
			{
				// Create port_filter_rule to do port matches without
				// having to reparse the string
				prometheus_conf::port_filter_rule pfr;
				prometheus_conf::portdef_to_pfrule(cond_it->second, pfr);
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

Json::Value prom_process::to_json(const prometheus_conf &conf) const
{
	Json::Value ret;
	ret["name"] = m_name;
	ret["pid"] = m_pid;
	ret["vpid"] = m_vpid;
	ret["ports"] = Json::Value(Json::arrayValue);

	ret["log_errors"] = conf.m_log_errors;
	if (conf.m_interval > 0)
		ret["interval"] = conf.m_interval;
	if (conf.m_max_metrics_per_proc > 0)
		ret["max_metrics"] = conf.m_max_metrics_per_proc;
	if (conf.m_max_tags_per_metric > 0)
		ret["max_tags"] = conf.m_max_tags_per_metric;
	if (m_path.size() > 0)
		ret["path"] = m_path;

	for(auto port : m_ports)
	{
		ret["ports"].append(Json::UInt(port));
	}

	return ret;
}
