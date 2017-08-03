#include <fnmatch.h>
#include "prometheus.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_int.h"
#include "analyzer_thread.h"

bool prometheus_conf::match(const sinsp_threadinfo *tinfo, const sinsp_container_info *container, set<uint16_t> &ports) const
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
	printf("Prometheus: process %s (%d): %d ports found, first is %d\n",
		tinfo->m_comm.c_str(), tinfo->m_pid, filtered_ports.size(),
		filtered_ports.empty() ? 0 : *(filtered_ports.begin()) );

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
						sprintf(reason, "port matched");
					break;
				}
				uint16_t port = atoi(cond.m_pattern.c_str());
				if (ports.find(port) == ports.end())
					matchcond = false;
				else
					sprintf(reason, "port = %s", cond.m_pattern.c_str());
				break;
			}
			case filter_condition::param_type::process_name:
				// matchcond = tinfo->m_comm.find(cond.m_pattern) != string::npos;
				matchcond = !fnmatch(cond.m_pattern.c_str(), tinfo->m_comm.c_str(), FNM_EXTMATCH);
				if (matchcond)
					sprintf(reason, "procname = %s", cond.m_pattern.c_str());
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
					sprintf(reason, "arg found: %s", cond.m_pattern.c_str());

				break;
			}
			case filter_condition::param_type::container_name:
				if (!container) {
					matchcond = false;
					break;
				}
				matchcond = !fnmatch(cond.m_pattern.c_str(), container->m_name.c_str(), FNM_EXTMATCH);
				if (matchcond)
					sprintf(reason, "container.name = %s", container->m_name.c_str());
				break;
			case filter_condition::param_type::container_image:
				if (!container) {
					matchcond = false;
					break;
				}
				matchcond = !fnmatch(cond.m_pattern.c_str(), container->m_image.c_str(), FNM_EXTMATCH);
				if (matchcond)
					sprintf(reason, "container.image = %s", container->m_image.c_str());
				break;
			default:
				printf("Condition for param_type %d not yet implemented\n",
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
			printf("Process %d matches prometheus rule: %d: %s\n", tinfo->m_pid,
				rn, reason);
			if (rule.m_include)
				ports = filtered_ports;
			return rule.m_include;
		}
		rn++;
	}
	// printf("Prometheus: %s (%d) not matched\n", tinfo->m_comm.c_str(), tinfo->m_tid);
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
		{ "container.label", container_label },
		{ "process.name", process_name },
		{ "process.cmdline", process_cmdline }
	};

	auto it = param_map.find(pstr);
	if (it != param_map.end())
		return(it->second);

	return param_type::string;
}

bool YAML::convert<prometheus_conf>::decode(const YAML::Node &node, prometheus_conf &rhs)
{
	/*
	 * Example:
	 * prometheus:
	 *   enabled: true
	 *   filter:
	 *     - include:
	 *       port: 8900
	 *     - include:
	 *       container.image: sysdig/agent
	 *     - exclude:
	 *       container.image: cassandra
	 */
	auto enabled_node = node["enabled"];
	if(enabled_node.IsScalar())
	{
		rhs.m_enabled = enabled_node.as<bool>();
	}
	auto log_errors_node = node["log_errors"];
	if(log_errors_node.IsScalar())
	{
		rhs.m_log_errors = log_errors_node.as<bool>();
	}
	auto interval_node = node["interval"];
	if(interval_node.IsScalar())
	{
		rhs.m_interval = interval_node.as<int>();
	}
	auto metperproc_node = node["max_metrics_per_process"];
	if(metperproc_node.IsScalar())
	{
		rhs.m_max_metrics_per_proc = metperproc_node.as<int>();
	}
	auto tagspermet_node = node["max_tags_per_metric"];
	if(tagspermet_node.IsScalar())
	{
		rhs.m_max_tags_per_metric = tagspermet_node.as<int>();
	}

	auto portfilter_node = node["port_filter"];
	if (portfilter_node.IsSequence())
	{
		for (const auto& rule_node : portfilter_node)
		{
			if (!rule_node.IsMap()) 
				continue;

			for (auto rule_it = rule_node.begin();
				rule_it != rule_node.end(); rule_it++)
			{
				prometheus_conf::port_filter_rule rule;
				if (rule_it->first.IsScalar())
				{
					rule.m_include = (rule_it->first.as<string>() == "include");
				}
				printf("port filter rule: %s, type %d\n", rule.m_include ?
					"include" : "exclude", rule_it->second.Type());

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
				rhs.m_port_rules.emplace_back(rule);
			}
		}
	}

	auto filter_node = node["filter"];
	if (filter_node.IsSequence())
	{
		for (const auto& rule_node :  filter_node)
		{
			if (!rule_node.IsMap()) 
				continue;

			for (auto rule_it = rule_node.begin();
				rule_it != rule_node.end(); rule_it++)
			{
				prometheus_conf::filter_rule rule;
				if (rule_it->first.IsScalar())
				{
					rule.m_include = (rule_it->first.as<string>() == "include");
				}
				if (!rule_it->second.IsMap())
					continue; // The rule conditions should be in map form

				for (auto cond_it = rule_it->second.begin();
					cond_it != rule_it->second.end(); cond_it++)
				{
					prometheus_conf::filter_condition cond;
					bool got_param = false;
					if (cond_it->first.IsScalar())
					{
						cond.m_param = cond_it->first.as<string>();
						cond.m_param_type = prometheus_conf::filter_condition::param2type(cond.m_param);
						if (!cond.m_param.empty()) {
							got_param = true;
						}
					}
					if (cond_it->second.IsScalar())
					{
						cond.m_pattern = cond_it->second.as<string>();
					}
					if (got_param)
					{
						rule.m_cond.emplace_back(cond);
					}
				}
				if (!rule.m_cond.empty())
				{
					rhs.m_rules.emplace_back(rule);
				}
			}
		}
	}
	
	return true;
}

Json::Value prom_process::to_json() const
{
	Json::Value ret;
	ret["name"] = m_name;
	ret["pid"] = m_pid;
	ret["vpid"] = m_vpid;
	ret["ports"] = Json::Value(Json::arrayValue);
	for(auto port : m_ports)
	{
		ret["ports"].append(Json::UInt(port));
	}

	return ret;
}
