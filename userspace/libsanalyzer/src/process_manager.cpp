#include "process_manager.h"

object_filter_config::object_filter_config_data process_manager::c_process_filter("definition of process filter to be used during flush",
										  "process",
										  "flush_filter");

type_config<bool> process_manager::c_process_flush_filter_enabled(false,
								  "enable process flush filtering",
								  "process",
								  "flush_filter_enabled");

type_config<uint32_t> process_manager::c_top_processes_per_host(1,
								"report the top N processes of each stat category before reporting whitelisted processes",
								"process",
								"top_n_per_host");

type_config<uint32_t> process_manager::c_top_processes_per_container(1,
								     "report the top N processes of each stat category before reporting whitelisted processes",
								     "process",
								     "top_n_per_container");

type_config<uint32_t> process_manager::c_process_limit(250,
						       "rough limit of processes to emit",
						       "process",
						       "limit");

type_config<bool> process_manager::c_always_send_app_checks(false,
							    "legacy config to force all processes which have app checks to be high priority. Users should instead define a filter which matches all app checks.",
							    "app_checks_always_send");

process_manager::process_manager()
	: m_flush_filter("process flush filter")
{
	std::vector<object_filter_config::filter_rule> rules = c_process_filter.get();
	if (c_always_send_app_checks.get())
	{
		object_filter_config::filter_rule all_app_checks("all app checks",
								 true,
								 {object_filter_config::filter_condition(object_filter_config::filter_condition::param_type::app_check_match,
													 "",
													 "*",
													 {})},
								 object_filter_config::rule_config());
		rules.insert(rules.begin(), all_app_checks);
	}


	m_flush_filter.set_rules(rules);
}

const object_filter& process_manager::get_flush_filter() const
{
	return m_flush_filter;
}
