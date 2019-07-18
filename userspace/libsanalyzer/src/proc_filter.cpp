#include <fnmatch.h>
#include "proc_filter.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_int.h"
#include "analyzer_thread.h"
#include "infrastructure_state.h"
#include <utils.h>
#include <sstream>

namespace proc_filter{

std::set<uint16_t> filter_ports(const std::set<uint16_t>& sports,
		const std::vector<object_filter_config::port_filter_rule>& rules)
{
	std::set<uint16_t> start_ports = sports;
	std::set<uint16_t> filtered_ports;

	for (const auto& portrule: rules)
	{
		if (start_ports.empty())
			break;
		std::set<uint16_t> matched_ports;
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

#ifndef CYGWING_AGENT
// Returns a boolean pair. The first indicates if the rule matched,
// the second if the rule should be applied
std::pair<bool, bool> conf::match_rule(const object_filter_config::filter_rule &rule, int rule_num, const sinsp_threadinfo *tinfo,
		 const sinsp_threadinfo *mtinfo, const sinsp_container_info *container,
		 const infrastructure_state &infra_state,
		 std::function<bool (const object_filter_config::filter_rule &rule)> on_match,
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
		if (cond.m_param_type != object_filter_config::filter_condition::param_type::all) {
			*generic_match = false;
		}

		// If a rule has multiple conditions, they must all be met.
		bool matchcond = true;
		switch(cond.m_param_type) {
		case object_filter_config::filter_condition::param_type::all:
			// Catch all rule. Nothing to do
			reason << "all";
			break;
		case object_filter_config::filter_condition::param_type::port:
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
		case object_filter_config::filter_condition::param_type::process_name:
			if (tinfo == nullptr) {
				matchcond = false;
				break;
			}
			matchcond = !fnmatch(cond.m_pattern.c_str(), tinfo->m_comm.c_str(), FNM_EXTMATCH);
			if (matchcond) {
				reason << "procname = " << cond.m_pattern;
			}
			break;
		case object_filter_config::filter_condition::param_type::process_cmdline:
			{
				if (tinfo == nullptr) {
					matchcond = false;
					break;
				}

				// Should this match include exe and arguments?
				if ((tinfo->m_exe.find(cond.m_pattern) == std::string::npos) &&
				    find_if(tinfo->m_args.begin(), tinfo->m_args.end(),
					    [&cond](const std::string& arg)
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
		case object_filter_config::filter_condition::param_type::container_name:
			if (!container) {
				matchcond = false;
				break;
			}
			matchcond = !fnmatch(cond.m_pattern.c_str(), container->m_name.c_str(), FNM_EXTMATCH);
			if (matchcond) {
				reason << "container.name = " << container->m_name;
			}
			break;
		case object_filter_config::filter_condition::param_type::container_image:
			if (!container) {
				matchcond = false;
				break;
			}
			matchcond = !fnmatch(cond.m_pattern.c_str(), container->m_image.c_str(), FNM_EXTMATCH);
			if (matchcond) {
				reason << "container.image = " << container->m_image;
			}
			break;
		case object_filter_config::filter_condition::param_type::container_label:
			{
				const std::string *lbl = object_filter_config::get_cont_label(container, cond.m_param);
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
		case object_filter_config::filter_condition::param_type::k8s_annotation:
		case object_filter_config::filter_condition::param_type::tag:
			{
				std::string val;
				if (!container) {
					matchcond = false;
					break;
				}
				infrastructure_state::uid_t c_uid = std::make_pair("container", container->m_id);

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
		case object_filter_config::filter_condition::param_type::app_check_match:
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
		 std::function<bool (const object_filter_config::filter_rule &rule)> on_match,
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
	std::vector<object_filter_config::filter_rule> *rules) const
{
	for (const auto& rule: rules ? *rules : m_rules)
	{
		for (const auto& cond: rule.m_cond)
		{
			if ((cond.m_param_type != object_filter_config::filter_condition::param_type::k8s_annotation) &&
				(cond.m_param_type != object_filter_config::filter_condition::param_type::tag))
				continue;

			reg(cond.m_param);
			g_logger.format(sinsp_logger::SEV_INFO,
				"%s: registering annotation %s", m_context.c_str(),
				cond.m_param.c_str());
		}
		if (rule.m_config.m_port_subst)
		{
			auto tokens = object_filter_config::get_str_tokens(rule.m_config.m_port);
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
			auto tokens = object_filter_config::get_str_tokens(rule.m_config.m_path);
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
				auto tokens = object_filter_config::get_str_tokens(option.second);
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
				auto tokens = object_filter_config::get_str_tokens(tag.second);
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

