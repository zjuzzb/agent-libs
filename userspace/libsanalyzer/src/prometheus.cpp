#ifndef CYGWING_AGENT
#include <fnmatch.h>
// #include "../dragent/configuration.h"
#include "analyzer_int.h"
#include "analyzer_thread.h"
#include "common_logger.h"
#include "infrastructure_state.h"
#include "prometheus.h"
#include "promscrape.h"
#include "sinsp.h"
#include "sinsp_int.h"

#include <utils.h>

using namespace std;

namespace
{
COMMON_LOGGER();
string replace_tokens(const string src,
                      const sinsp_container_info* container,
                      const infrastructure_state& infra_state,
                      infrastructure_state::uid_t c_uid)
{
	string ret;
	size_t lpos = 0;
	size_t pos;
	while ((pos = src.find('{', lpos)) != string::npos)
	{
		if (pos > lpos)
			ret += src.substr(lpos, pos - lpos);

		size_t bc = src.find('}', pos);
		if (bc == string::npos)
		{
			lpos = pos + 1;
			break;
		}
		string token = src.substr(pos + 1, bc - (pos + 1));
		if (!token.compare(0,
		                   object_filter_config::CONTAINER_LABEL.size(),
		                   object_filter_config::CONTAINER_LABEL))
		{
			const string* strptr = object_filter_config::get_cont_label(
			    container,
			    token.substr(object_filter_config::CONTAINER_LABEL.size() + 1, string::npos));
			if (strptr)
			{
				ret += *strptr;
			}
		}
		else
		{
			string value;
			bool found = infra_state.find_tag(c_uid, token, value);
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

}  // namespace

// Statically initialize the prometheus timeout config
// Min value : 01 sec
// Max value : 60 sec
// Default   : 01 sec
type_config<uint32_t>::ptr prometheus_conf::c_prometheus_timeout =
    type_config_builder<uint32_t>(
        1 /*default value of 1 second*/,
        "The value in seconds we wait to scrape prometheus endpoints before timing out.",
        "prometheus",
        "timeout")
        .min(1)
        .max(60)
        .build();

bool prometheus_conf::get_rule_params(const object_filter_config::filter_rule& rule,
                                      const thread_analyzer_info* tinfo,
                                      const sinsp_container_info* container,
                                      const infrastructure_state& infra_state,
                                      bool use_host_filter,
                                      prom_params_t& params) const
//	set<uint16_t> &out_ports, string &out_path, map<string, string> &out_options,
//	map<string, string> &out_tags)
{
	// In the process_filter only include rules (that match) get applied
	// In the host_filter all matching rules apply
	if (!rule.m_include && !use_host_filter)
		return false;

	infrastructure_state::uid_t c_uid;
	if (container)
	{
		c_uid = make_pair("container", container->m_id);
	}

	set<uint16_t> start_ports;
	if (!use_host_filter)
	{
		start_ports = tinfo->listening_ports();
	}
	params.ports = start_ports;
	if (!rule.m_config.m_port.empty())
	{
		params.ports.clear();
		string pstr = rule.m_config.m_port_subst
		                  ? replace_tokens(rule.m_config.m_port, container, infra_state, c_uid)
		                  : rule.m_config.m_port;
		uint16_t p = atoi(pstr.c_str());

		// In the host_filter, which is used to select remote endpoints we cannot
		// check if the port is actually listened to, so we just use it.
		if (use_host_filter)
		{
			params.ports.emplace(p);
		}
		else
		{
			// If port is non-null we assume only that port should be
			// scanned, so a mismatch means we don't scan.
			// If the port is 0 (because a token couldn't be resolved
			// or otherwise) we can still try using a port-filter.
			if (p && (start_ports.find(p) != start_ports.end()))
			{
				LOG_DEBUG("Prometheus autodetection: process %d defined port %d found",
				          (int)tinfo->m_pid,
				          (int)p);
				params.ports.emplace(p);
			}
			else if (p)
			{
				LOG_DEBUG(
				    "Prometheus autodetection: process %d defined port %d not found, not scanning",
				    (int)tinfo->m_pid,
				    (int)p);
				// port is non-null but not found -> skip scan.
				return false;
			}
		}
	}
	if (use_host_filter)
	{
		// For remote scraping we require at least a configured port or url
		// XXX: Handling of "urls" still needs to be added downstream, see SMAGENT-2294
		if (params.ports.empty() &&
		    (rule.m_config.m_options.find("url") == rule.m_config.m_options.end()) &&
		    (rule.m_config.m_options.find("urls") == rule.m_config.m_options.end()))
		{
			LOG_DEBUG(
			    "Prometheus autodetection: host_filter rule is missing url,urls or "
			    "host/port config");
			return false;
		}
	}
	else
	{
		// If we found a matching configured port we skip
		// the port-filter
		if (!rule.m_config.m_port_rules.empty() &&
		    (rule.m_config.m_port.empty() || params.ports.empty()))
		{
			params.ports = proc_filter::filter_ports(start_ports, rule.m_config.m_port_rules);
		}
		if (params.ports.empty())
		{
			return false;
		}
	}
	if (!rule.m_config.m_path.empty())
	{
		params.path = rule.m_config.m_path_subst
		                  ? replace_tokens(rule.m_config.m_path, container, infra_state, c_uid)
		                  : rule.m_config.m_path;
	}
	if (rule.m_config.m_options_subst && !rule.m_config.m_options.empty())
	{
		for (const auto& option : rule.m_config.m_options)
		{
			string value = replace_tokens(option.second, container, infra_state, c_uid);
			LOG_DEBUG("Prometheus token subst: process %d, option %s: %s = %s",
			          (int)tinfo->m_pid,
			          option.first.c_str(),
			          option.second.c_str(),
			          value.c_str());
			if (value.empty())
			{
				// Not scanning when configured option is empty because an
				// annotation may not be available in the hierarchy yet and we
				// don't want the appcheck to get blacklisted prematurely
				// Seen with user/pass coming from service annotations
				LOG_DEBUG(
				    "Prometheus autodetection: process %d defined option %s is empty, not scanning",
				    (int)tinfo->m_pid,
				    option.first.c_str());
				return false;
			}
			params.options[option.first] = move(value);
		}
	}
	else
	{
		params.options = rule.m_config.m_options;
	}
	if (rule.m_config.m_tags_subst && !rule.m_config.m_tags.empty())
	{
		for (const auto& tag : rule.m_config.m_tags)
		{
			string value = replace_tokens(tag.second, container, infra_state, c_uid);
			LOG_DEBUG("Prometheus token subst: process %d, tag %s: %s = %s",
			          (int)tinfo->m_pid,
			          tag.first.c_str(),
			          tag.second.c_str(),
			          value.c_str());
			if (value.empty())
			{
				// Just logging when tag is empty but still scanning
				LOG_DEBUG("Prometheus autodetection: process %d defined tag %s is empty",
				          (int)tinfo->m_pid,
				          tag.first.c_str());
			}
			params.tags[tag.first] = move(value);
		}
	}
	else
	{
		params.tags = rule.m_config.m_tags;
	}
	return true;
}

bool prometheus_conf::match_and_fill(const thread_analyzer_info* tinfo,
                                     thread_analyzer_info* mtinfo,
                                     const sinsp_container_info* container,
                                     const infrastructure_state& infra_state,
                                     vector<prom_process>& prom_procs,
                                     bool use_host_filter) const
{
	if (!m_enabled)
	{
		return false;
	}

	int rule_num = 0;

	// If use_host_filter is set, use the "remote_services" host rules and
	// apply all matching rules.
	// Otherwise we use the process_filter rules and stop after the first match
	for (const auto& rule : (use_host_filter) ? m_host_rules : m_rules)
	{
		prom_params_t params;

		std::function<bool(const object_filter_config::filter_rule& rule)> on_match =
		    [&](const object_filter_config::filter_rule& rule) -> bool {
			return get_rule_params(rule, tinfo, container, infra_state, use_host_filter, params);
		};

		std::pair<bool, bool> matched =
		    match_rule(rule, rule_num, tinfo, mtinfo, container, infra_state, on_match);

		// Did rule match
		if (matched.first)
		{
			// Should rule be applied
			if (matched.second)
			{
				std::unordered_map<std::string, std::string> infra_tags;
				// Look for infrastructure state name tags
				// Currently only used for promscrape to select relabeling rules,
				// so don't waste time if promscrape is not enabled
				if (promscrape::c_use_promscrape.get_value())
				{
					if (container)
					{
						infrastructure_state::uid_t c_uid;
						c_uid = make_pair("container", container->m_id);
						infrastructure_state::tag_cb_t infra_tag_cb =
						    [&infra_tags, &infra_state](
						        const std::pair<std::string, std::string>& tag,
						        bool& stop) -> int {
							std::string shortname;
							if (infra_state.match_name(tag.first, &shortname))
							{
								infra_tags[shortname] = tag.second;
								return 1;
							}
							return 0;
						};
						infra_state.iterate_parent_tags(c_uid, infra_tag_cb);

						// Promscrape can't enter the target namespace and in kubernetes
						// it probably won't be able to reach the target port through localhost.
						// If a host or url haven't been explicitly configured,
						// we look up the pod IP and use that.
						if ((params.options.find("host") == params.options.end()) &&
						    (params.options.find("url") == params.options.end()))
						{
							std::string podip = infra_state.get_parent_ip_address(c_uid);
							if (!podip.empty())
							{
								LOG_DEBUG("Prometheus: Found IP address %s for pid %ld",
								          podip.c_str(),
								          tinfo->m_pid);
								params.options["host"] = std::move(podip);
							}
						}
					}
					if (tinfo)
					{
						infra_tags["process"] = tinfo->m_comm;
					}
					infra_tags["host"] = sinsp_gethostname();
				}

				prom_process pp(tinfo->m_comm,
				                tinfo->m_pid,
				                tinfo->m_vpid,
				                tinfo->m_container_id,
				                params.ports,
				                params.path,
				                params.options,
				                params.tags,
				                std::move(infra_tags));
				prom_procs.emplace_back(pp);

				mtinfo->set_found_prom_check();
			}
			// If not using host_filter return after the first match
			if (!use_host_filter)
			{
				return matched.second;
			}
		}
		rule_num++;
	}
	return false;
}

void prometheus_conf::register_annotations(std::function<void(const std::string& str)> reg)
{
	base::register_annotations(reg);
	base::register_annotations(reg, &m_host_rules);
}

Json::Value prom_process::to_json(const prometheus_conf& conf) const
{
	Json::Value ret;
	ret["name"] = m_name;
	ret["pid"] = m_pid;
	ret["vpid"] = m_vpid;
	ret["ports"] = Json::Value(Json::arrayValue);

	ret["log_errors"] = conf.log_errors();
	if (conf.interval() > 0)
		ret["interval"] = conf.interval();
	if (conf.max_metrics_per_proc() > 0)
		ret["max_metrics"] = conf.max_metrics_per_proc();
	if (conf.max_tags_per_metric() > 0)
		ret["max_tags"] = conf.max_tags_per_metric();
	ret["histograms"] = conf.histograms();
	ret["ingest_raw"] = conf.ingest_raw();
	ret["ingest_calculated"] = conf.ingest_calculated();
	ret["timeout"] = prometheus_conf::c_prometheus_timeout->get_value();
	if (m_path.size() > 0)
		ret["path"] = m_path;

	for (auto port : m_ports)
	{
		ret["ports"].append(Json::UInt(port));
	}

	Json::Value opts;
	for (auto option : m_options)
	{
		opts[option.first] = option.second;
	}
	if (!opts.empty())
		ret["options"] = opts;

	Json::Value tags = Json::Value(Json::arrayValue);
	for (auto tag : m_tags)
	{
		// Transfer tag list as array
		tags.append(tag.first + ":" + tag.second);
	}
	if (!tags.empty())
		ret["tags"] = tags;

	return ret;
}

// Make sure we only scan any port only once per container or on host
// If multiple matching processes are listening to a port within the same
// container, pick the oldest
void prom_process::filter_procs(vector<prom_process>& procs,
                                threadinfo_map_t& threadtable,
                                const app_checks_proxy_interface::raw_metric_map_t& app_metrics,
                                uint64_t now)
{
	// TODO: Add search for existing prometheus metrics from promscrape. SMAGENT-2295
	// Set of container_id and listening port for non-expired prometheus metrics
	// to ensure we don't try scanning those ports again for a different pid.
	std::set<std::pair<string, uint16_t>> portmetricmap;
	// Populate port metric map based on app_metrics
	for (const auto& app_met_pid : app_metrics)
	{
		bool have_mets = false;
		for (const auto& app_met : app_met_pid.second)
		{
			if ((app_met.second->type() == app_check_data::check_type::PROMETHEUS) &&
			    (app_met.second->expiration_ts() > (now / ONE_SECOND_IN_NS)))
			{
				have_mets = true;
				break;
			}
		}
		if (!have_mets)
		{
			// This pid doesn't have unexpired prometheus metrics
			continue;
		}
		thread_analyzer_info* tinfo =
		    dynamic_cast<thread_analyzer_info*>(threadtable.get(app_met_pid.first));
		if (!tinfo)
		{
			LOG_DEBUG("Prometheus: Couldn't get thread info for pid %d", app_met_pid.first);
			continue;
		}

		string portstr;
		// Mark all this pid's ports as associated with the non-expired metrics
		for (uint16_t port : tinfo->listening_ports())
		{
			portstr = portstr + " " + to_string(port);
			portmetricmap.emplace(make_pair(tinfo->m_container_id, port));
		}
		LOG_TRACE("Prometheus filter: container %s, pid %d, unexpired metrics for ports %s",
		          tinfo->m_container_id.c_str(),
		          app_met_pid.first,
		          portstr.c_str());
	}

	if (procs.size() <= 1 && portmetricmap.empty())
		return;

	// Map by container_id and port number to prom_process pointer
	// Ideally we should key by net namespace but this is a little easier
	typedef std::map<uint16_t, prom_process*> portmap_t;
	std::map<string, portmap_t> containermap;

	for (auto& proc : procs)
	{
		sinsp_threadinfo* tinfo = threadtable.get(proc.m_pid);
		if (!tinfo)
		{
			LOG_INFO(
			    "Prometheus filter: Couldn't get thread info for pid %d, skipping port "
			    "uniqueness filter",
			    proc.m_pid);
			continue;
		}

		// Erase any ports for which unexpired metrics are known to exist
		for (auto it = proc.m_ports.begin(); it != proc.m_ports.end();)
		{
			if (portmetricmap.find(make_pair(tinfo->m_container_id, *it)) != portmetricmap.end())
			{
				LOG_DEBUG(
				    "Prometheus filter: removing scan for port %d (pid %ld) because "
				    "metrics already exist",
				    *it,
				    tinfo->m_pid);
				it = proc.m_ports.erase(it);
			}
			else
			{
				it++;
			}
		}

		if (containermap.find(tinfo->m_container_id) == containermap.end())
		{
			// Not found: add our ports
			portmap_t portmap;
			for (auto port : proc.m_ports)
			{
				portmap[port] = &proc;
			}
			if (!portmap.empty())
			{
				containermap[tinfo->m_container_id] = move(portmap);
			}
		}
		else
		{
			for (auto it = proc.m_ports.begin(); it != proc.m_ports.end();)
			{
				uint16_t port = *it;
				if (containermap[tinfo->m_container_id].find(port) ==
				    containermap[tinfo->m_container_id].end())
				{
					it++;
					continue;
				}
				// For every matching port determine the eldest process
				// We can probably rely on the clone timestamps
				// proc_process *oproc = proc.m_ports[portproc.first];
				prom_process* oproc = containermap[tinfo->m_container_id][port];
				sinsp_threadinfo* otinfo = threadtable.get(oproc->m_pid);
				if (!otinfo)
				{
					LOG_WARNING(
					    "Prometheus: Couldn't get thread info for pid %d, can't compare with %d",
					    oproc->m_pid,
					    proc.m_pid);
					ASSERT(0);
					it++;
					continue;
				}
				// Assuming the clone timestamps will be different
				if (otinfo->m_clone_ts <= tinfo->m_clone_ts)
				{
					LOG_DEBUG(
					    "Prometheus: both pids %d and %d are listening to %d %s%s, %d is older",
					    oproc->m_pid,
					    proc.m_pid,
					    port,
					    tinfo->m_container_id.empty() ? "on host" : "in container ",
					    tinfo->m_container_id.c_str(),
					    oproc->m_pid);
					// Other process is older, remove the port from our ports
					it = proc.m_ports.erase(it);
				}
				else
				{
					LOG_DEBUG(
					    "Prometheus: both pids %d and %d are listening to %d %s%s, %d is older",
					    oproc->m_pid,
					    proc.m_pid,
					    port,
					    tinfo->m_container_id.empty() ? "on host" : "in container ",
					    tinfo->m_container_id.c_str(),
					    proc.m_pid);
					// This process is older, remove port from the other process
					// We'll replace it in the portmap after this loop
					oproc->m_ports.erase(port);
					it++;
				}
			}
			// Place any ports this process has left into the portmap
			for (auto port : proc.m_ports)
			{
				containermap[tinfo->m_container_id][port] = &proc;
			}
		}
	}
	// Now remove any processes that don't have ports left.
	vector<prom_process>::iterator it;
	for (it = procs.begin(); it != procs.end();)
	{
		if (it->m_ports.empty())
		{
			LOG_DEBUG("Prometheus: no ports left to scan in pid %d", it->m_pid);
			it = procs.erase(it);
		}
		else
		{
			it++;
		}
	}
}
#endif  // CYGWING_AGENT
