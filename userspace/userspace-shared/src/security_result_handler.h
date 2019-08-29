#pragma once

namespace draiosproto {
class policy_events;
class throttled_policy_events;
class comp_results;
}

/**
 * virtual class that defines the API invoked when security results are ready.
 * Courtesy default implementations are provided.
 */
class security_result_handler
{
public:
        virtual void security_mgr_policy_events_ready(uint64_t ts_ns,
						      draiosproto::policy_events *events) = 0;

        virtual void security_mgr_throttled_events_ready(uint64_t ts_ns,
							 draiosproto::throttled_policy_events *events,
							 uint32_t total_throttled_count) = 0;

        virtual void security_mgr_comp_results_ready(uint64_t ts_ns,
						     const draiosproto::comp_results *results) = 0;
};

class security_result_handler_dummy : public security_result_handler
{
public:
        virtual void security_mgr_policy_events_ready(uint64_t ts_ns,
						      draiosproto::policy_events *events)
	{
	}

        virtual void security_mgr_throttled_events_ready(uint64_t ts_ns,
							 draiosproto::throttled_policy_events *events,
							 uint32_t total_throttled_count)
	{
	}

        virtual void security_mgr_comp_results_ready(uint64_t ts_ns,
						     const draiosproto::comp_results *results)
	{
	}
};
