#pragma once

// Responsible for managing actions that result from policies matching
// events.

#include <infrastructure_state.h>

class security_mgr;

class SINSP_PUBLIC security_actions
{
public:
	typedef google::protobuf::RepeatedPtrField<draiosproto::action> actions;
	typedef google::protobuf::RepeatedPtrField<draiosproto::v2action> v2actions;

	security_actions();
	virtual ~security_actions();

	void init(security_mgr *mgr,
		  const std::string &agent_container_id,
		  std::shared_ptr<coclient> &coclient,
		  infrastructure_state_iface *infra_state);

	// Perform the actions for the provided policy, using the
	// information from the given policy event. Any action results
	// will be added to the policy event.
	//
	// This object then owns the policy event and is responsible
	// for deleting it.
	//
	void perform_actions(uint64_t ts_ns,
			     const sinsp_threadinfo *tinfo,
			     const std::string &policy_name,
			     const std::string &policy_type,
			     const actions &actions,
			     const v2actions &v2actions,
			     draiosproto::policy_event *event);

	// Check the list of outstanding actions and see if any are
	// complete. If they are, pass the policy event to the security mgr.
	void check_outstanding_actions(uint64_t ts_ns);

	// Garbage collect the active docker actions
	void periodic_cleanup(uint64_t ts_ns);

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

		std::shared_ptr<draiosproto::policy_event> m_event;
		uint32_t m_num_remaining_actions;

		// If true, this policy event must be sent as soon as
		// all actions are complete.
		bool m_send_now;
	};

	// Wrapper around draiosproto::action_result/v2action_result
	// that allows for unified setters of successful/errmsg.
	class actions_result
	{
	public:
		actions_result();

		void add_result(draiosproto::action_result *result);
		void add_v2result(draiosproto::v2action_result *v2result);

		void set_successful(bool succesful);
		void set_errmsg(const std::string &errmsg);
		void set_token(const std::string &token);

		std::string to_string();

	private:
		draiosproto::action_result *m_result;
		draiosproto::v2action_result *m_v2result;
	};

	// Return whether or not this event has an action result of
	// the specified type. Return a pointer to that action result
	// or NULL.
	draiosproto::action_result *has_action_result(draiosproto::policy_event *evt,
						      const draiosproto::action_type &atype);

	// Note that an action has completed.
	void note_action_complete(const std::shared_ptr<actions_state> &astate);

	void perform_container_action(uint64_t ts_ns,
				      const std::string &policy_name,
				      sdc_internal::container_cmd_type cmd,
				      std::string &container_id,
				      const std::string &action,
				      std::shared_ptr<actions_result> result,
				      std::shared_ptr<actions_state> astate);

	void perform_capture_action(uint64_t ts_ns,
								const std::string &policy_name,
								std::string &container_id,
								uint64_t pid,
								const draiosproto::capture_action &capture,
								shared_ptr<actions_result> result,
								shared_ptr<actions_state> astate);

	std::vector<std::shared_ptr<actions_state>> m_outstanding_actions;

	// Ensures that only a single docker action (of any type) can
	// be performed on a container at once
	std::map<std::string,uint64_t> m_active_container_actions;

	security_mgr *m_mgr;
	std::string m_agent_container_id;
	bool m_has_outstanding_actions;
	std::shared_ptr<coclient> m_coclient;
	infrastructure_state_iface *m_infra_state;
};

