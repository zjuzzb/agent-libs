#include <string>

#include <Poco/UUIDGenerator.h>

#include "logger.h"

#include "security_mgr.h"
#include "security_policy.h"

using namespace std;

security_policy::security_policy(security_mgr *mgr,
				 dragent_configuration *configuration,
				 uint64_t id,
				 const std::string &name,
				 const google::protobuf::RepeatedPtrField<draiosproto::action> &actions,
				 shared_ptr<coclient> &coclient,
				 bool enabled)
	: m_mgr(mgr),
	  m_configuration(configuration),
	  m_id(id),
	  m_name(name),
	  m_enabled(enabled),
	  m_coclient(coclient)
{
	m_print.SetSingleLineMode(true);

	for(auto &action : actions)
	{
		m_actions.push_back(action);
	}
}

security_policy::~security_policy()
{
}

std::string &security_policy::to_string()
{
	m_str = m_name + " [" + std::to_string(m_id) + "] actions=";

	for(auto it = m_actions.begin(); it != m_actions.end(); it++)
	{
		string tmp;

		m_str += (it == m_actions.begin() ? "" : ",");
		m_print.PrintToString(*it, &tmp);
		m_str += tmp;
	}

	m_str += " enabled=" + std::to_string(m_enabled);

	return m_str;
}

std::string &security_policy::name()
{
	return m_name;
}

bool security_policy::perform_actions(sinsp_evt *evt, draiosproto::policy_event *event)
{
	m_outstanding_actions.emplace_back(event, m_actions.size());
	actions_state &astate = m_outstanding_actions.back();

	sinsp_threadinfo *tinfo = evt->get_thread_info();
	sinsp_container_info container_info;
	string container_id;

	if(tinfo)
	{
		container_id = tinfo->m_container_id;
	}

	for(auto &action : m_actions)
	{
		draiosproto::action_result *result = astate.m_event->add_action_results();
		result->set_type(action.type());
		result->set_successful(true);

		coclient::response_cb_t callback = [result, &astate, this] (bool successful, google::protobuf::Message *response_msg)
		{
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
			astate.m_num_remaining_actions--;

			string tmp;
			m_print.PrintToString(*result, &tmp);
			g_log->debug(string("Docker cmd action result: ") + tmp);
		};

		string tmp;
		bool apply_scope = false;
		string errstr;

		switch(action.type())
		{
			// XXX/mstemm, technically, I need to start this only after the truly asynch actions have completed, to ensure the policy event message is sent before any sinsp capture chunk messages.
		case draiosproto::ACTION_CAPTURE:

			result->set_token(Poco::UUIDGenerator().createRandom().toString());
			if (action.capture().has_is_limited_to_container())
			{
				apply_scope = action.capture().is_limited_to_container();
			}

			if(!m_mgr->start_capture(evt->get_ts(),
						 m_name,
						 result->token(),
						 (action.capture().has_filter() ? action.capture().filter() : ""),
						 action.capture().before_event_ns(),
						 action.capture().after_event_ns(),
						 apply_scope,
						 container_id,
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
				astate.m_send_now = true;
			}

			astate.m_num_remaining_actions--;

			m_print.PrintToString(*result, &tmp);
			g_log->debug(string("Capture action result: ") + tmp);

			break;
		case draiosproto::ACTION_PAUSE:
			m_coclient->perform_docker_cmd(sdc_internal::PAUSE, container_id, callback);
			break;
		case draiosproto::ACTION_STOP:
			m_coclient->perform_docker_cmd(sdc_internal::STOP, container_id, callback);
			break;
		default:
			string errstr = string("Policy Action ") + std::to_string(action.type()) + string(" not implemented yet");
			result->set_successful(false);
			result->set_errmsg(errstr);
			g_log->debug(errstr);
		}
	}

	return true;
}


void security_policy::check_outstanding_actions(uint64_t ts_ns)
{
	list<actions_state>::iterator i = m_outstanding_actions.begin();
	while(i != m_outstanding_actions.end())
	{
		if(i->m_num_remaining_actions == 0)
		{
			m_mgr->accept_policy_event(ts_ns, i->m_event, i->m_send_now);
			m_outstanding_actions.erase(i++);
		}
		else
		{
			i++;
		}
	}
}

falco_security_policy::falco_security_policy(security_mgr *mgr,
					     dragent_configuration *configuration,
					     const draiosproto::policy &policy,
					     sinsp *inspector,
					     shared_ptr<falco_engine> &falco_engine,
					     shared_ptr<falco_events> &falco_events,
					     shared_ptr<coclient> &coclient)
	: security_policy(mgr,
			  configuration,
			  policy.id(),
			  policy.name(),
			  policy.actions(),
			  coclient,
			  policy.enabled()),
	  m_falco_engine(falco_engine),
	  m_falco_events(falco_events),
	  m_formatters(inspector)
{

	// Use the name and tags filter to create a ruleset. We'll use
	// this ruleset to run only the subset of rules we're
	// interested in.
	string all_rules = ".*";

	// We *only* want those rules selected by name/tags, so first disable all rules.
	m_falco_engine->enable_rule(all_rules, false, m_name);

	if(policy.falco_details().rule_filter().has_name())
	{
		m_rule_filter = policy.falco_details().rule_filter().name();
		m_falco_engine->enable_rule(m_rule_filter, true, m_name);
	}

	for(auto tag : policy.falco_details().rule_filter().tags())
	{
		m_tags.insert(tag);
	}

	m_falco_engine->enable_rule_by_tag(m_tags, true, m_name);

	m_ruleset_id = m_falco_engine->find_ruleset_id(m_name);
}

falco_security_policy::~falco_security_policy()
{
}

draiosproto::policy_event *falco_security_policy::process_event(sinsp_evt *evt)
{
	if(m_enabled && m_falco_engine && ((evt->get_info_flags() & EF_DROP_FALCO) == 0))
	{
		try {
			unique_ptr<falco_engine::rule_result> res = m_falco_engine->process_event(evt, m_ruleset_id);
			if(res)
			{
				draiosproto::policy_event *event = new draiosproto::policy_event();
				draiosproto::falco_event_detail *fdetail = event->mutable_falco_details();
				string output;
				sinsp_threadinfo *tinfo = evt->get_thread_info();

				g_log->debug("Event matched falco policy: rule=" + res->rule);

				if(m_falco_events && m_configuration->m_security_send_monitor_events)
				{
					m_falco_events->generate_user_event(res);
				}

				event->set_timestamp_ns(evt->get_ts());
				event->set_policy_id(m_id);
				if(tinfo && !tinfo->m_container_id.empty())
				{
					event->set_container_id(tinfo->m_container_id);
				}

				fdetail->set_rule(res->rule);

				m_formatters.tostring(evt, res->format, &output);
				fdetail->set_output(output);

				return event;
			}
		}
		catch (falco_exception& e)
		{
			g_log->error("Error processing event against falco engine: " + string(e.what()));
		}
	}

	return NULL;
}

std::string &falco_security_policy::to_string()
{
	string tmp;

	m_fstr = security_policy::to_string();

	m_fstr += " rule_filter=\"" + m_rule_filter + "\" tags=[";
	for(auto it = m_tags.begin(); it != m_tags.end(); it++)
	{
		m_fstr += (it == m_tags.begin() ? "" : ",");
		m_fstr += *it;
	}

	m_fstr += "]";

	return m_fstr;
}
