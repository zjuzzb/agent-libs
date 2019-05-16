#include "object_filter.h"
#include <fnmatch.h>
#include "analyzer_thread.h"

std::string process_name_filter::no_data = "";
std::string container_name_filter::no_data = "";
std::string container_image_filter::no_data = "";

bool process_cmd_line_filter::matches(const object_filter_args& arg,
				      bool& exclude,
				      bool& high_priority,
				      std::string& reason) const
{
	if (!arg.m_tinfo)
	{
		return false;
	}

	// Should this match include exe and arguments?
	if (arg.m_tinfo->m_exe.find(m_pattern) == string::npos &&
	    find_if(arg.m_tinfo->m_args.begin(),
		    arg.m_tinfo->m_args.end(),
		    [this](const string& candidate) {
			    return !fnmatch(m_pattern.c_str(),
					    candidate.c_str(),
					    FNM_EXTMATCH);
		    }) == arg.m_tinfo->m_args.end())
	{
		return false;
	}


	exclude = this->exclude_on_match();
	high_priority = true;
	reason = "arg_found: " + m_pattern;
	return true;
}

bool port_filter::matches(const object_filter_args& arg,
			  bool& exclude,
			  bool& high_priority,
			  std::string& reason) const
{
	if (!arg.m_tinfo || !arg.m_tinfo->m_ainfo)
	{
		return false;
	}

	auto start_ports = arg.m_tinfo->m_ainfo->listening_ports();
	auto ports = filter_ports(start_ports, m_ports);

	if (!ports.empty())
	{
		reason = std::to_string(ports.size()) + " ports match: " + std::to_string(*(ports.begin()));
		exclude = this->exclude_on_match();
		high_priority = true;
		return true;
	}

	return false;
}

std::set<uint16_t> port_filter::filter_ports(const std::set<uint16_t>& sports,
					     const vector<object_filter_config::port_filter_rule>& rules)
{
	std::set<uint16_t> start_ports = sports;
	std::set<uint16_t> filtered_ports;

	for (const auto& portrule: rules)
	{
		if (start_ports.empty())
		{
			break;
		}

		set<uint16_t> matched_ports;
		for (const auto& port : start_ports)
		{
			if (portrule.m_use_set) {
				if (portrule.m_port_set.find(port) != portrule.m_port_set.end())
				{
					matched_ports.insert(port);
				}
			}
			else
			{
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

bool container_label_filter::matches(const object_filter_args& arg,
				     bool& exclude,
				     bool& high_priority,
				     std::string& reason) const
{
	if (!arg.m_container)
	{
		return false;
	}

	const std::string *lbl = object_filter_config::get_cont_label(arg.m_container, m_label);

	if (!lbl)
	{
		return false;
	}

	if (fnmatch(m_pattern.c_str(),
		    lbl->c_str(),
		    FNM_EXTMATCH))
	{
		return false;
	}

	exclude = this->exclude_on_match();
	high_priority = true;
	reason = m_label + " equals " + m_pattern;
	return true;
}

bool tag_filter::matches(const object_filter_args& arg,
			 bool& exclude,
			 bool& high_priority,
			 std::string& reason) const
{
	if (!arg.m_container || !arg.m_is)
	{
		return false;
	}

	infrastructure_state::uid_t c_uid;
	c_uid = std::make_pair("container", arg.m_container->m_id);

	std::string val;
	bool found = arg.m_is->find_tag(c_uid, m_label, val);

	if (!found)
	{
		return false;
	}

	if (fnmatch(m_pattern.c_str(), val.c_str(), FNM_EXTMATCH))
	{
		return false;
	}

	exclude = this->exclude_on_match();
	high_priority = true;
	reason = m_label + " equals " + m_pattern;
	return true;
}

bool app_check_filter::matches(const object_filter_args& arg,
			       bool& exclude,
			       bool& high_priority,
			       std::string& reason) const
{
	if (!arg.m_mtinfo || !arg.m_mtinfo->m_ainfo)
	{
		return false;
	}

	if (!arg.m_mtinfo->m_ainfo->found_app_check_by_fnmatch(m_pattern))
	{
		return false;
	}

	exclude = this->exclude_on_match();
	high_priority = true;
	reason = "found app check: " + m_pattern; 
	return true;
}

bool object_filter::matches(const sinsp_threadinfo* tinfo,
			    const sinsp_threadinfo* mtinfo,
			    const sinsp_container_info* container,
			    const infrastructure_state* is,
			    bool* generic_match,
			    const object_filter_config::filter_rule** match_rule) const
{
	bool exclude = false;
	bool high_priority = false;
	std::string reason = "";
	uint32_t rule_number;
	bool match = m_filter->matches(object_filter_args(tinfo,
							  mtinfo,
							  container,
							  is),
				       exclude,
				       high_priority,
				       reason,
				       rule_number);

	if (match)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
				"%s: Object with tpid %d, mtpid %d, container %s matches rule: %s",
				m_name.c_str(),
				tinfo ? (uint32_t)tinfo->m_pid : -1,
				mtinfo ? (uint32_t)mtinfo->m_pid : -1,
				container ? container->m_name.c_str() : "",
				reason.c_str());

		if (match_rule)
		{
			*match_rule = &m_rules[rule_number];
		}

		if (generic_match)
		{
			*generic_match = !high_priority;
		}

		return !exclude;
	}

	return false;
}

void object_filter::set_rules(const std::vector<object_filter_config::filter_rule>& rules)
{
	m_rules = rules;


	std::list<std::shared_ptr<base_filter<object_filter_args>>> rule_list;
	if (m_rules.empty())
	{
		rule_list.push_back({std::make_shared<all_filter<object_filter_args>>(false)});
	}
	else
	{
		for (const auto& rule : m_rules)
		{
			std::list<std::shared_ptr<base_filter<object_filter_args>>> conditions;
			for (const auto& condition : rule.m_cond)
			{
				std::shared_ptr<base_filter<object_filter_args>> filter;
				switch (condition.m_param_type)
				{
				case object_filter_config::filter_condition::param_type::none:
					g_logger.format(sinsp_logger::SEV_WARNING,
							"Object filter rule is type none: param %s",
							condition.m_param.c_str());
					continue;
				case object_filter_config::filter_condition::param_type::port:
					filter = std::make_shared<port_filter>(condition.m_port_match);
					break;
				case object_filter_config::filter_condition::param_type::container_image:
					filter = std::make_shared<container_image_filter>(condition.m_pattern);
					break;
				case object_filter_config::filter_condition::param_type::container_name:
					filter = std::make_shared<container_name_filter>(condition.m_pattern);
					break;
				case object_filter_config::filter_condition::param_type::container_label:
					filter = std::make_shared<container_label_filter>(condition.m_param,
											  condition.m_pattern);
					break;
				case object_filter_config::filter_condition::param_type::process_name:
					filter = std::make_shared<process_name_filter>(condition.m_pattern);
					break;
				case object_filter_config::filter_condition::param_type::process_cmdline:
					filter = std::make_shared<process_cmd_line_filter>(condition.m_pattern);
					break;
				case object_filter_config::filter_condition::param_type::app_check_match:
					filter = std::make_shared<app_check_filter>(condition.m_pattern);
					break;
				case object_filter_config::filter_condition::param_type::k8s_annotation:
				case object_filter_config::filter_condition::param_type::tag:
					filter = std::make_shared<tag_filter>(condition.m_param,
									      condition.m_pattern);
					break;
				case object_filter_config::filter_condition::param_type::all:
					filter = std::make_shared<all_filter<object_filter_args>>(false);
					break;
				}

				conditions.push_back(filter);
			}

			rule_list.push_back(std::make_shared<and_filter<object_filter_args>>(!rule.m_include,
											     conditions));
		}
	}
	m_filter = std::make_shared<priority_filter<object_filter_args>>(rule_list);
}

void object_filter::register_annotations(std::function<void(const std::string&)> reg) const
{
	for (const auto& rule: m_rules)
	{
		for (const auto& cond: rule.m_cond)
		{
			if ((cond.m_param_type != object_filter_config::filter_condition::param_type::k8s_annotation) &&
			    (cond.m_param_type != object_filter_config::filter_condition::param_type::tag))
			{
				continue;
			}

			reg(cond.m_param);
			g_logger.format(sinsp_logger::SEV_INFO,
					"%s: registering annotation %s",
					m_name.c_str(),
					cond.m_param.c_str());
		}
		if (rule.m_config.m_port_subst)
		{
			auto tokens = object_filter_config::get_str_tokens(rule.m_config.m_port);
			for (const auto &token : tokens)
			{
				reg(token);
				g_logger.format(sinsp_logger::SEV_INFO,
						"%s: registering port annotation %s",
						m_name.c_str(),
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
						"%s: registering path annotation %s",
						m_name.c_str(),
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
							"%s: registering option annotation %s", m_name.c_str(),
							token.c_str());
				}
			}
		}
	}
}

