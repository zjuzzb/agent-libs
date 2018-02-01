#pragma once

// Responsible for managing actions that result from policies matching
// events.

class SINSP_PUBLIC security_actions
{
public:
	security_actions();
	virtual ~security_actions();

	void init(security_mgr *mgr,
		  std::shared_ptr<coclient> &coclient);

	// Perform the actions for the provided policy, using the
	// information from the given policy event. Any action results
	// will be added to the policy event.
	//
	// This object then owns the policy event and is responsible
	// for deleting it.
	//
	void perform_actions(sinsp_evt *evt,
			     const security_policy *policy,
			     draiosproto::policy_event *event);

	// Check the list of outstanding actions and see if any are
	// complete. If they are, pass the policy event to the security mgr.
	void check_outstanding_actions(uint64_t ts_ns);

protected:
	// Keeps track of any policy events and their outstanding
	// actions. When all actions are complete, the policy will
	// send the policy event message.
	class actions_state
	{
	public:
		actions_state(draiosproto::policy_event *event,
			      uint32_t num_remaining_actions)
			: m_event(event),
  			  m_num_remaining_actions(num_remaining_actions),
			  m_send_now(false)
		{
		};

		virtual ~actions_state()
		{
		}

		shared_ptr<draiosproto::policy_event> m_event;
		uint32_t m_num_remaining_actions;

		// If true, this policy event must be sent as soon as
		// all actions are complete.
		bool m_send_now;
	};

	// Return whether or not this event has an action result of
	// the specified type. Return a pointer to that action result
	// or NULL.
	draiosproto::action_result *has_action_result(draiosproto::policy_event *evt,
						      const draiosproto::action_type &atype);

	// Note that an action has completed.
	void note_action_complete(actions_state &astate);

	std::vector<actions_state> m_outstanding_actions;
	security_mgr *m_mgr;
	bool m_has_outstanding_actions;
	std::shared_ptr<coclient> m_coclient;
};

