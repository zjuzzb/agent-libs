#include <Poco/UUIDGenerator.h>

#include <google/protobuf/text_format.h>

#include "coclient.h"

#include "security_mgr.h"
#ifndef CYGWING_AGENT
#include "security_action.h"
#include "container_config.h"

using namespace std;

namespace
{
COMMON_LOGGER();

type_config<bool> c_support_actions(true,
                                    "indicates whether taking actions based on policies is supported",
                                    "security",
                                    "actions_enabled");
}

security_actions::actions_result::actions_result()
	: m_result(NULL), m_v2result(NULL)
{
}

void security_actions::actions_result::add_result(draiosproto::action_result *result)
{
	m_result = result;
	m_v2result = NULL;
}

void security_actions::actions_result::add_v2result(draiosproto::v2action_result *v2result)
{
	m_result = NULL;
	m_v2result = v2result;
}

void security_actions::actions_result::set_successful(bool successful)
{
	if(m_result)
	{
		m_result->set_successful(successful);
	}

	if(m_v2result)
	{
		m_v2result->set_successful(successful);
	}
}

void security_actions::actions_result::set_errmsg(const std::string &errmsg)
{
	if(m_result)
	{
		m_result->set_errmsg(errmsg);
	}

	if(m_v2result)
	{
		m_v2result->set_errmsg(errmsg);
	}
}

void security_actions::actions_result::set_token(const std::string &token)
{
	if(m_result)
	{
		m_result->set_token(token);
	}

	if(m_v2result)
	{
		m_v2result->set_token(token);
	}
}

std::string security_actions::actions_result::to_string()
{
	if(m_result)
	{
		return m_result->DebugString();
	}
	else if(m_v2result)
	{
		return m_v2result->DebugString();
	}
	else
	{
		return string("No result object");
	}
}

security_actions::security_actions()
	: m_has_outstanding_actions(false)
{
}

security_actions::~security_actions()
{
}

void security_actions::init(security_mgr *mgr,
			    const std::string &agent_container_id,
			    std::shared_ptr<coclient> &coclient,
			    infrastructure_state_iface *infra_state)
{
	m_mgr = mgr;
	m_agent_container_id = agent_container_id;
	m_coclient = coclient;
	m_infra_state = infra_state;
}

void security_actions::perform_container_action(uint64_t ts_ns,
						const std::string &policy_name,
						sdc_internal::container_cmd_type cmd,
						std::string &container_id,
						const std::string &action,
						shared_ptr<actions_result> result,
						shared_ptr<actions_state> astate)
{
	const google::protobuf::EnumDescriptor* descriptor = sdc_internal::container_cmd_type_descriptor();

	LOG_DEBUG("Performing Policy Event Action Container policy="
		  + policy_name +
		  " container_id=" + container_id +
		  " action=" + descriptor->FindValueByNumber(cmd)->name());

	if(container_id == "")
	{
		// Docker actions against empty containers trivially succeed
		result->set_successful(true);
		note_action_complete(astate);
	}
	else if(container_id == m_agent_container_id)
	{
		// The agent can't perform container actions on itself
		result->set_successful(false);
		result->set_errmsg("Container id is agent container");
		note_action_complete(astate);
	}
	else
	{
		auto container = m_infra_state->get_container_info(container_id);
		if (!container) {
			result->set_successful(false);
			result->set_errmsg("Container not found");
			note_action_complete(astate);
		}
		else if(m_active_container_actions.find(container_id) != m_active_container_actions.end())
		{
			std::string msg = "Skipping back-to-back container action " +
				action +
				" for container " + container_id;

			LOG_DEBUG(msg);

			result->set_successful(false);
			result->set_errmsg("RPC Not successful");

			note_action_complete(astate);
		}
		else
		{
			switch (container->m_type)
			{
				case sinsp_container_type::CT_DOCKER:
					m_active_container_actions.insert(pair<string, uint64_t>(container_id, ts_ns));
					m_coclient->perform_docker_cmd(cmd, container_id, [result, astate, this] (bool successful, google::protobuf::Message *response_msg)
					{
						google::protobuf::TextFormat::Printer print;

						sdc_internal::docker_command_result *res = (sdc_internal::docker_command_result *) response_msg;
						if(!successful)
						{
							result->set_successful(false);
							result->set_errmsg("RPC Not successful");
						}

						if(!res->successful())
						{
							result->set_successful(false);
							result->set_errmsg("Could not perform docker command: " + res->errstr());
						}

						note_action_complete(astate);

						LOG_DEBUG(string("Docker cmd action result: ") + result->to_string());
					});
					break;
				case sinsp_container_type::CT_CONTAINERD:
				case sinsp_container_type::CT_CRI:
				case sinsp_container_type::CT_CRIO:
					m_active_container_actions.insert(pair<string, uint64_t>(container_id, ts_ns));
					m_coclient->perform_cri_cmd(c_cri_socket_path->get_value(), cmd, container_id,
						[result, astate, this] (bool successful, google::protobuf::Message *response_msg)
					{
						google::protobuf::TextFormat::Printer print;

						sdc_internal::cri_command_result *res = (sdc_internal::cri_command_result *) response_msg;
						if(!successful)
						{
							result->set_successful(false);
							result->set_errmsg("RPC Not successful");
						}

						if(!res->successful())
						{
							result->set_successful(false);
							result->set_errmsg("Could not perform cri-o command: " + res->errstr());
						}

						note_action_complete(astate);

						LOG_DEBUG(string("Cri-o cmd action result: ") + result->to_string());
					});
					break;
				default:
					result->set_successful(false);
					result->set_errmsg(string("Unsupported container type ") + to_string(container->m_type));
					note_action_complete(astate);
			}
		}
	}
}

void security_actions::perform_capture_action(uint64_t ts_ns,
					      const std::string &policy_name,
					      std::string &container_id,
					      uint64_t pid,
					      const draiosproto::capture_action &capture,
					      shared_ptr<actions_result> result,
					      shared_ptr<actions_state> astate)
{
	bool apply_scope = false;
	std::string token = Poco::UUIDGenerator().createRandom().toString();
	std::string errstr;

	LOG_DEBUG("Performing Policy Event Action Capture policy= "
		  + policy_name +
		  " " + capture.DebugString());

	result->set_token(token);
	if (capture.has_is_limited_to_container())
	{
		apply_scope = capture.is_limited_to_container();
	}

	LOG_DEBUG("Starting capture action");
	if(!m_mgr->start_capture(ts_ns,
				 policy_name,
				 token,
				 (capture.has_filter() ? capture.filter() : ""),
				 capture.before_event_ns(),
				 capture.after_event_ns(),
				 apply_scope,
				 container_id,
				 pid,
				 errstr))
	{
		result->set_successful(false);
		result->set_errmsg(errstr);
	}
	else
	{
		// We had at least one capture action
		// that was successful, so we must
		// send the policy event immediately.
		astate->m_send_now = true;
	}

	note_action_complete(astate);

	LOG_DEBUG(string("Capture action result: ") + result->to_string());
}

void security_actions::perform_actions(uint64_t ts_ns,
				       const sinsp_threadinfo *tinfo,
				       const std::string &policy_name,
				       const std::string &policy_type,
				       const actions &actions,
				       const v2actions &v2actions,
				       draiosproto::policy_event *event)
{
	google::protobuf::TextFormat::Printer print;

	m_outstanding_actions.emplace_back(make_shared<actions_state>(event, actions.size() + v2actions.size()));
	shared_ptr<actions_state> astate = m_outstanding_actions.back();

	sinsp_container_info container_info;
	string container_id;
	uint64_t pid = 0;

	if(tinfo)
	{
		container_id = tinfo->m_container_id;
		pid = tinfo->m_pid;
	}

	for(auto &action : actions)
	{
		draiosproto::action_result *result = astate->m_event->add_action_results();
		result->set_type(action.type());
		result->set_successful(true);
		shared_ptr<actions_result> sresult = make_shared<actions_result>();
		sresult->add_result(result);

		string errstr;

		bool action_handled = true;
		if (c_support_actions.get_value())
		{
			// Although the messaging for actions is
			// general purpose, allowing any action to be
			// a part of a policy, regardless of type,
			// only captures are supported for k8s audit
			// policy types.
			if(policy_type == "falco" ||
			   policy_type == "list_matching" ||
			   policy_type == "") {

				switch(action.type())
				{
				case draiosproto::ACTION_CAPTURE:
					perform_capture_action(ts_ns, policy_name, container_id, pid, action.capture(), sresult, astate);
					break;
				case draiosproto::ACTION_PAUSE:
					perform_container_action(ts_ns, policy_name, sdc_internal::PAUSE, container_id, std::to_string(action.type()), sresult, astate);
					break;
				case draiosproto::ACTION_STOP:
					perform_container_action(ts_ns, policy_name, sdc_internal::STOP, container_id, std::to_string(action.type()), sresult, astate);
					break;
				default:
					action_handled = false;
				}
				if (!result->successful())
				{
					LOG_WARNING("Policy Action " + std::to_string(action.type()) + " failed: " +
						    result->errmsg());
				}
			}
			else if (policy_type == "k8s_audit")
			{
				switch(action.type())
				{
				case draiosproto::ACTION_CAPTURE:
					perform_capture_action(ts_ns, policy_name, container_id, pid, action.capture(), sresult, astate);
					break;
				default:
					action_handled = false;
				}
			} else {
				action_handled = false;
			}
		} else {
			action_handled = false;
		}

		if (!action_handled) {
			string errstr = string("Policy Action ") + std::to_string(action.type()) + string(" not implemented yet for policy type ") + policy_type;
			result->set_successful(false);
			result->set_errmsg(errstr);
			note_action_complete(astate);
			LOG_DEBUG(errstr);
		}
	}

	for(auto &action : v2actions)
	{
		draiosproto::v2action_result *result = astate->m_event->add_v2action_results();
		result->set_type(action.type());
		result->set_successful(true);

		shared_ptr<actions_result> sresult = make_shared<actions_result>();
		sresult->add_v2result(result);

		string errstr;

		bool action_handled = true;
		if (c_support_actions.get_value())
		{
			if(policy_type == "falco" ||
			   policy_type == "list_matching" ||
			   policy_type == "") {
				switch(action.type())
				{
				case draiosproto::V2ACTION_CAPTURE:
					perform_capture_action(ts_ns, policy_name, container_id, pid, action.capture(), sresult, astate);
					break;
				case draiosproto::V2ACTION_PAUSE:
					perform_container_action(ts_ns, policy_name, sdc_internal::PAUSE, container_id, std::to_string(action.type()), sresult, astate);
					break;
				case draiosproto::V2ACTION_STOP:
					perform_container_action(ts_ns, policy_name, sdc_internal::STOP, container_id, std::to_string(action.type()), sresult, astate);
					break;
				case draiosproto::V2ACTION_KILL:
					perform_container_action(ts_ns, policy_name, sdc_internal::KILL, container_id, std::to_string(action.type()), sresult, astate);
					break;
				default:
					action_handled = false;
				}
				if (!result->successful())
				{
					LOG_WARNING("Policy Action " + std::to_string(action.type()) + " failed: " +
						    result->errmsg());
				}
			}
			else if (policy_type == "k8s_audit")
			{
				switch(action.type())
				{
				case draiosproto::V2ACTION_CAPTURE:
					perform_capture_action(ts_ns, policy_name, container_id, pid, action.capture(), sresult, astate);
					break;
				default:
					action_handled = false;
				}
			} else {
				action_handled = false;
			}
		} else {
			action_handled = false;
		}

		if (!action_handled) {
			string errstr = string("Policy Action ") + std::to_string(action.type()) + string(" not implemented yet for policy type ") + policy_type;
			result->set_successful(false);
			result->set_errmsg(errstr);
			note_action_complete(astate);
			LOG_DEBUG(errstr);
		}
	}

	if(astate->m_num_remaining_actions == 0)
	{
		m_has_outstanding_actions = true;
	}
}


draiosproto::action_result *security_actions::has_action_result(draiosproto::policy_event *evt,
							       const draiosproto::action_type &atype)
{
	for(int i=0; i<evt->action_results_size(); i++)
	{
		draiosproto::action_result *aresult = evt->mutable_action_results(i);
		if(aresult->type() == atype)
		{
			return aresult;
		}
	}

	return NULL;
}

void security_actions::note_action_complete(const shared_ptr<actions_state> &astate)
{
	if(--astate->m_num_remaining_actions == 0)
	{
		m_has_outstanding_actions = true;
	}
}

void security_actions::check_outstanding_actions(uint64_t ts_ns)
{
	if (!m_has_outstanding_actions)
	{
		return;
	}

	auto no_outstanding_actions = [ts_ns, this] (shared_ptr<actions_state> &act)
	{
		if(act->m_num_remaining_actions == 0)
		{
			m_mgr->send_policy_event(ts_ns, act->m_event, act->m_send_now);

			const draiosproto::action_result *aresult;

			if((aresult = has_action_result(act->m_event.get(), draiosproto::ACTION_CAPTURE)) &&
			   aresult->successful())
			{
				string token = aresult->token();

				if(token.empty())
				{
					LOG_ERROR("Could not find capture token for policy event that had capture action?");
				}
				else
				{
					// If one of the actions was a capture, when
					// we scheduled the capture we deferred
					// actually sending the capture data. Start
					// sending the data now.
					m_mgr->start_sending_capture(token);
				}
			}
			return true;
		}

		return false;
	};

	m_outstanding_actions.erase(remove_if(m_outstanding_actions.begin(),
					      m_outstanding_actions.end(),
					      no_outstanding_actions),
				    m_outstanding_actions.end());

	m_has_outstanding_actions = false;
}

void security_actions::periodic_cleanup(uint64_t ts_ns)
{
	// This roughly correlates to the 30 second delay we have for
	// docker stop actions, but the real goal is to avoid a flood
	// of docker operations for a single container, so they don't
	// need to be exactly the same.
	for (auto it = m_active_container_actions.begin(); it != m_active_container_actions.end(); )
	{
		if(ts_ns > it->second && (ts_ns-it->second) > 30 * ONE_SECOND_IN_NS)
		{
			LOG_DEBUG("Removing container action for " + it->first);
			m_active_container_actions.erase(it++);
		}
		else
		{
			it++;
		}
	}
}
#endif // CYGWING_AGENT
