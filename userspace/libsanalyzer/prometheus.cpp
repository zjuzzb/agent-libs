#include <fnmatch.h>
// #include "../dragent/configuration.h"
#include "prometheus.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_int.h"
#include "analyzer_thread.h"
#include <utils.h>

bool prometheus_conf::match(const sinsp_threadinfo *tinfo, const sinsp_threadinfo *mtinfo, const sinsp_container_info *container, set<uint16_t> &ports) const
{
	if (!m_enabled)
		return false;
	auto start_ports = tinfo->m_ainfo->listening_ports();
	decltype(start_ports) filtered_ports;

	// Testing
	char reason[256];
	memset(reason, 0, 256);
	int rn = 0;
	for (const auto& portrule: m_port_rules)
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
	if (m_port_rules.empty()) {
		filtered_ports = start_ports;
	}

	if (filtered_ports.empty())
		return false;

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
				// Just looking for single port for the moment
				// Should change to match port range
				auto ports = tinfo->m_ainfo->listening_ports();
				if (cond.m_pattern == "matched")
				{
					if (filtered_ports.empty())
						matchcond = false;
					else
						snprintf(reason, sizeof(reason), "port matched");
					break;
				}
				uint16_t port = atoi(cond.m_pattern.c_str());
				if (ports.find(port) == ports.end())
					matchcond = false;
				else
					snprintf(reason, sizeof(reason), "port = %s", cond.m_pattern.c_str());
				break;
			}
			case filter_condition::param_type::process_name:
				// matchcond = tinfo->m_comm.find(cond.m_pattern) != string::npos;
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
						// return arg.find(cond.m_pattern) != string::npos;
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
				if (!container) {
					matchcond = false;
					break;
				}
				const auto& lval_it = container->m_labels.find(cond.m_param);
				if ((lval_it == container->m_labels.end()) ||
					fnmatch(cond.m_pattern.c_str(), lval_it->second.c_str(), FNM_EXTMATCH))
				{
					matchcond = false;
					break;
				}
				matchcond = true;
				snprintf(reason, sizeof(reason), "container.label.%s = %s", cond.m_param.c_str(),
					lval_it->second.c_str());
				break;
			}
			case filter_condition::param_type::app_check_match:
				matchcond = mtinfo->m_ainfo->found_app_check_by_fnmatch(cond.m_pattern);
				if (matchcond)
					snprintf(reason, sizeof(reason), "app_check found for %s", cond.m_pattern.c_str());
				break;
			default:
				g_logger.format(sinsp_logger::SEV_INFO, 
					"Condition for param_type %d not yet implemented\n",
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
				"Process %d matches prometheus rule: %d: %s\n",
				(int)tinfo->m_pid, rn, reason);
			if (rule.m_include)
				ports = filtered_ports;
			return rule.m_include;
		}
		rn++;
	}
	return false;
}

prometheus_conf::filter_condition::param_type 
prometheus_conf::filter_condition::param2type(std::string pstr)
{
	const std::string cont_label_str = "container.label";
	static const map<std::string, param_type> param_map =
	{
		{ "port", port },
		{ "container.image", container_image },
		{ "container.name", container_name },
		{ cont_label_str, container_label },
		{ "process.name", process_name },
		{ "process.cmdline", process_cmdline },
		{ "appcheck.match", app_check_match }
	};

	auto it = param_map.find(pstr);
	if (it != param_map.end())
		return(it->second);
	
	if (!pstr.compare(0, cont_label_str.size(), cont_label_str))
		return container_label;

	return param_type::string;
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
		rule.m_include = (rule_it->first.as<string>() == "include");

		if (rule_it->second.IsSequence())
		{
			rule.m_use_set = true;
			for (const auto& port_node : rule_it->second)
			{
				if (!port_node.IsScalar())
					continue;

				uint16_t p = port_node.as<uint16_t>();
				if (p) {
					rule.m_port_set.insert(p);
				}
			}
		}
		else if (rule_it->second.IsScalar())
		{
			rule.m_use_set = false;
			// Parse single port or range
			string str = rule_it->second.as<string>();
			auto delim = str.find("-");
			rule.m_range_start = atoi(str.substr(0, delim).c_str());
			rule.m_range_end = (delim == string::npos) ?
				rule.m_range_start :
				atoi(str.substr(delim + 1, string::npos).c_str());
		}
		else
		{
			continue;
		}

		rhs = rule;
		return true;
	}
	return false;
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

			prometheus_conf::filter_condition cond;
			cond.m_param = cond_it->first.as<string>();
			if (cond.m_param.empty())
				continue;
			cond.m_param_type = prometheus_conf::filter_condition::param2type(cond.m_param);
			if (cond.m_param_type == prometheus_conf::filter_condition::
				param_type::container_label)
			{
				// strip "container.label" from param
				cond.m_param = cond.m_param.substr(strlen("container.label")+1, string::npos);
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

	for(auto port : m_ports)
	{
		ret["ports"].append(Json::UInt(port));
	}

	return ret;
}
