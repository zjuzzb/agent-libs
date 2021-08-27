#pragma once
#include "infrastructure_state.h"
#include "security_rule.h"

#include <event.h>
#include <list>
class sinsp_evt_delay_filter
{
private:
	using delay_filter_t = std::function<bool(const std::string&,
	                                          const security_rules::match_result&,
	                                          const sinsp_container_manager& container_manager)>;

	using delay_filter_list_t = std::vector<delay_filter_t *>;

	delay_filter_list_t create_filter_list();

public:

	/**
	 * check the delaying filters to see if we should delay the event
	 */
	bool should_delay(const std::string* container_id,
	                  const std::list<security_rules::match_result>&,
	                  const sinsp_container_manager&);
};
