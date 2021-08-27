#include "sinsp_evt_delay_filter.h"

namespace
{
COMMON_LOGGER();
}

static type_config<bool> should_delay_actions(false,
                                              "should delay if actions present",
                                              "falco_alert_wait_container_info",
                                              "delay_actions");

static type_config<bool> check_image_scope(false,
                                           "should check image predicates",
                                           "falco_alert_wait_container_info",
                                           "check_image_scope");

// generate list of filter functions based on the config options
sinsp_evt_delay_filter::delay_filter_list_t sinsp_evt_delay_filter::create_filter_list()
{
	// check for actions, if any do not delay.
	static delay_filter_t check_actions_func = [](const std::string& container_id,
	                                              const security_rules::match_result& result,
	                                              const sinsp_container_manager& container_manager)
	{
		if (!result.m_policy->v2actions().empty() || !result.m_policy->actions().empty())
		{
			LOG_INFO("Not delaying the event due to the policy actions to be taken");
			return false;
		}
		return true;
	};

	// image fields to check for empty
	static const std::vector<std::string> container_keys = {"container.image",
	                                                        "container.image.repo",
	                                                        "container.image.tag",
	                                                        "container.image.id",
	                                                        "container.image.digest"};

	// check for predicates involving image fields, if none do not delay
	static delay_filter_t check_predicates_func =
	    [](const std::string& container_id,
	       const security_rules::match_result& result,
	       const sinsp_container_manager& container_manager)
	{
		for (const auto& predicate : result.m_policy->scope_predicates())
		{
			if (std::find(container_keys.begin(), container_keys.end(), predicate.key()) !=
			    container_keys.end())
			{
				LOG_INFO("Not delaying the event - it's not depending on image predicates");
				return true;
			}
		}
		return false;
	};

	// generate list of filter functions based on the config options
	delay_filter_list_t f_list;

	// check actions
	if (!should_delay_actions.get_value())
	{
		f_list.push_back(&check_actions_func);
	}

	// check image scope
	if (check_image_scope.get_value())
	{
		f_list.push_back(&check_predicates_func);
	}

	return f_list;
}

// check whether the event should be delayed
bool sinsp_evt_delay_filter::should_delay(const std::string* container_id,
                                          const std::list<security_rules::match_result>& results,
                                          const sinsp_container_manager& container_manager)
{

	// unknown container id
	if (container_id == nullptr || container_id->empty())
	{
		return false;
	}

	// check if container info already in
	const auto ci = container_manager.get_container(*container_id);
	if (ci == nullptr || ci->m_lookup_state == sinsp_container_lookup_state::SUCCESSFUL)
	{
		LOG_DEBUG("not delaing event: is_ci_null=%d, lookup_state=%d",
		          ci == nullptr,
		          ci == nullptr ? -1 : (int)ci->m_lookup_state);
		return false;
	}

	// run configured filters
	delay_filter_list_t f_list = create_filter_list();
	if (f_list.empty())
	{
		return true;
	}

	// check each result in the list, fail delaying even a single result fails
	for (const auto& result : results)
	{
		for (auto f : f_list)
		{
			if (!(*f)(*container_id, result, container_manager))
			{
				return false;
			}
		}
	}
	return true;
}
