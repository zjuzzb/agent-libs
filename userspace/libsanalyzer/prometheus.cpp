#include <fnmatch.h>
// #include "../dragent/configuration.h"
#include "prometheus.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_int.h"
#include "analyzer_thread.h"
#include "infrastructure_state.h"
#include <utils.h>

namespace {

string replace_tokens(const string src, const sinsp_container_info *container,
		infrastructure_state *infra_state, infrastructure_state::uid_t c_uid)
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
		if (!token.compare(0, proc_filter::CONT_LABEL.size(), proc_filter::CONT_LABEL))
		{
			const string *strptr = proc_filter::get_cont_label(container,
				token.substr(proc_filter::CONT_LABEL.size()+1, string::npos));
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

}

bool prometheus_conf::match(const sinsp_threadinfo *tinfo,
		const sinsp_threadinfo *mtinfo, const sinsp_container_info *container,
		infrastructure_state *infra_state,
		set<uint16_t> &out_ports, string &out_path) const
{
	return base::match(tinfo, mtinfo, container, infra_state,
		[&](const proc_filter::filter_rule &rule) -> bool
		{
			if (!rule.m_include) return false;

			auto start_ports = tinfo->m_ainfo->listening_ports();
			infrastructure_state::uid_t c_uid;
			if (container) {
				c_uid = make_pair("container", container->m_id);
			}

			out_ports = start_ports;
			if (!rule.m_config.m_port.empty())
			{
				out_ports.clear();
				string pstr = rule.m_config.m_port_subst ?
						replace_tokens(rule.m_config.m_port, container, infra_state, c_uid) :
						rule.m_config.m_port;
				uint16_t p = atoi(pstr.c_str());
				// If port is non-null we assume only that port should be
				// scanned, so a mismatch means we don't scan.
				// If the port is 0 (because a token couldn't be resolved
				// or otherwise) we can still try using a port-filter.
				if (p && (start_ports.find(p) != start_ports.end()))
				{
					g_logger.format(sinsp_logger::SEV_DEBUG,
						"Prometheus autodetection: process %d defined port %d found",
						(int)tinfo->m_pid, (int)p);
					out_ports.emplace(p);
				}
				else if (p)
				{
					g_logger.format(sinsp_logger::SEV_DEBUG,
						"Prometheus autodetection: process %d defined port %d not found, not scanning",
						(int)tinfo->m_pid, (int)p);
					// port is non-null but not found -> skip scan.
					return false;
				}
			}
			// If we found a matching configured port we skip
			// the port-filter
			if (!rule.m_config.m_port_rules.empty() &&
				(rule.m_config.m_port.empty() || out_ports.empty()))
			{
				out_ports = filter_ports(start_ports, rule.m_config.m_port_rules);
			}
			if (out_ports.empty()) {
				return false;
			}
			if (!rule.m_config.m_path.empty())
			{
				out_path = rule.m_config.m_path_subst ?
						replace_tokens(rule.m_config.m_path, container, infra_state, c_uid) :
						rule.m_config.m_path;
			}
			return true;
		});
}

Json::Value prom_process::to_json(const prometheus_conf &conf) const
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
	if (m_path.size() > 0)
		ret["path"] = m_path;

	for(auto port : m_ports)
	{
		ret["ports"].append(Json::UInt(port));
	}

	return ret;
}
