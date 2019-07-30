#include <Poco/UUIDGenerator.h>

#include <google/protobuf/text_format.h>

#include "coclient.h"

#include "security_mgr.h"
#ifndef CYGWING_AGENT
#include "security_action.h"

using namespace std;

security_actions::security_actions()
	: m_has_outstanding_actions(false)
{
}

security_actions::~security_actions()
{
}

void security_actions::init(security_mgr *mgr,
			    std::shared_ptr<coclient> &coclient)
{
	m_mgr = mgr;
	m_coclient = coclient;
}

void security_actions::perform_docker_action(uint64_t ts_ns,
					     sdc_internal::docker_cmd_type cmd,
					     std::string &container_id,
					     const draiosproto::action &action,
					     draiosproto::action_result *result,
					     shared_ptr<actions_state> astate)
{
	if(container_id == "")
	{
		// Docker actions against empty containers trivially succeed
		result->set_successful(true);
		note_action_complete(astate);
	}
	else
	{
		coclient::response_cb_t callback = [result, astate, this] (bool successful, google::protobuf::Message *response_msg)
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

			string tmp;
			print.PrintToString(*result, &tmp);
			g_log->debug(string("Docker cmd action result: ") + tmp);
		};

		if(m_active_docker_actions.find(container_id) != m_active_docker_actions.end())
		{
			std::string msg = "Skipping back-to-back docker action " +
				std::to_string(action.type()) +
				" for container " + container_id;

			g_log->debug(msg);

			result->set_successful(false);
			result->set_errmsg("RPC Not successful");

			note_action_complete(astate);
		}
		else
		{
			m_active_docker_actions.insert(pair<string,uint64_t>(container_id, ts_ns));
			m_coclient->perform_docker_cmd(cmd, container_id, callback);
		}
	}
}

void security_actions::perform_actions(uint64_t ts_ns,
				       sinsp_threadinfo *tinfo,
				       const std::string &policy_name,
				       const actions &actions,
				       draiosproto::policy_event *event)
{
	google::protobuf::TextFormat::Printer print;

	m_outstanding_actions.emplace_back(make_shared<actions_state>(event, actions.size()));
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

		string tmp;
		bool apply_scope = false;
		string errstr;

		switch(action.type())
		{
		case draiosproto::ACTION_CAPTURE:

			result->set_token(Poco::UUIDGenerator().createRandom().toString());
			if (action.capture().has_is_limited_to_container())
			{
				apply_scope = action.capture().is_limited_to_container();
			}

			if(!m_mgr->start_capture(ts_ns,
						 policy_name,
						 result->token(),
						 (action.capture().has_filter() ? action.capture().filter() : ""),
						 action.capture().before_event_ns(),
						 action.capture().after_event_ns(),
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

			print.PrintToString(*result, &tmp);
			g_log->debug(string("Capture action result: ") + tmp);

			break;
		case draiosproto::ACTION_PAUSE:
			perform_docker_action(ts_ns, sdc_internal::PAUSE, container_id, action, result, astate);
			break;
		case draiosproto::ACTION_STOP:
			perform_docker_action(ts_ns, sdc_internal::STOP, container_id, action, result, astate);
			break;
		default:
			string errstr = string("Policy Action ") + std::to_string(action.type()) + string(" not implemented yet");
			result->set_successful(false);
			result->set_errmsg(errstr);
			g_log->debug(errstr);
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
					g_log->error("Could not find capture token for policy event that had capture action?");
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
	for (auto it = m_active_docker_actions.begin(); it != m_active_docker_actions.end(); )
	{
		if(ts_ns > it->second && (ts_ns-it->second) > 30 * ONE_SECOND_IN_NS)
		{
			g_log->debug("Removing docker action for " + it->first);
			m_active_docker_actions.erase(it++);
		}
		else
		{
			it++;
		}
	}
}
#endif // CYGWING_AGENT
