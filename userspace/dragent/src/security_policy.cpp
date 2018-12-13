#ifndef CYGWING_AGENT
#include <string>
#include <memory>

#include "logger.h"
#include "json_evt.h"

#include "security_mgr.h"
#include "security_policy.h"

extern sinsp_filter_check_list g_filterlist;

using namespace std;
using namespace path_prefix_map_ut;

uint64_t security_policy::m_next_order = 0;

security_policy::security_policy(const draiosproto::policy &policy)
	: draiosproto::policy(policy),
	m_order(m_next_order++)
{
}

security_policy::~security_policy()
{
}

bool security_policy::has_action(const draiosproto::action_type &atype)
{
	for(auto &action : actions())
	{
		if(action.type() == atype)
		{
			return true;
		}
	}

	return false;
}

bool security_policy::match_scope(std::string container_id, sinsp_analyzer *analyzer) const
{
	if(!analyzer)
	{
		return true;
	}

	if(!container_scope() && !host_scope()) {
		// This should never occur. Err on the side of allowing the policy to run.
		g_log->error("Impossible scope with host/container_scope == false. Allowing policy anyway.");
		return true;
	}

	if((container_id.empty() && !host_scope()) || (!container_id.empty() && !container_scope())) {
		// This policy isn't meant to be applied to this event
		return false;
	}

	infrastructure_state::uid_t uid;
	if (!container_id.empty())
	{
		uid = make_pair("container", container_id);
	} else
	{
		uid = make_pair("host", analyzer->get_configuration_read_only()->get_machine_id());
	}

	return scope_predicates().empty() || analyzer->infra_state()->match_scope(uid, scope_predicates());
}

// This object owns event_detail but not the policy.
security_policies::match_result::match_result()
{
	m_policy = NULL;
	m_detail = NULL;
}
security_policies::match_result::match_result(const security_policy *policy,
					      draiosproto::policy_type policies_type,
					      draiosproto::policy_subtype policies_subtype,
					      uint32_t item,
					      draiosproto::event_detail *detail,
					      draiosproto::match_effect effect,
					      const google::protobuf::RepeatedPtrField<std::string> &ofk,
					      const std::string &baseline_id)
	: m_policy(policy),
	  m_policies_type(policies_type),
	  m_policies_subtype(policies_subtype),
	  m_item(item),
	  m_detail(detail),
	  m_effect(effect),
	  m_ofk(ofk),
	  m_baseline_id(baseline_id)
{
}

security_policies::match_result::~match_result()
{
	if(m_detail)
	{
		delete m_detail;
	}
}

bool security_policies::match_result::compare(const match_result &a, const match_result &b)
{
	if (a.policy()->order() == b.policy()->order())
	{
		if(a.policies_type() == b.policies_type())
		{
			if(a.policies_subtype() == b.policies_subtype())
			{
				return (a.item() < b.item());
			}
			else
			{
				return((uint32_t) a.policies_subtype() < (uint32_t) b.policies_subtype());
			}
		}
		else
		{
			return((uint32_t) a.policies_type() < (uint32_t) b.policies_type());
		}
	}
	else
	{
		return (a.policy()->order() < b.policy()->order());
	}
}

bool security_policies::match_result::compare_ptr(const match_result *a, const match_result *b)
{
	return compare(*a, *b);
}

security_policies::security_policies()
	: m_num_loaded_policies(0)
{
	m_evttypes.assign(PPM_EVENT_MAX+1, false);
	m_evtsources.assign(ESRC_MAX+1, false);
}

security_policies::~security_policies()
{
}

void security_policies::init(dragent_configuration *configuration,
			     sinsp *inspector,
			     std::shared_ptr<security_evt_metrics> metrics)
{
	m_configuration = configuration;
	m_inspector = inspector;
	m_metrics = metrics;

	m_formatters = make_unique<sinsp_evt_formatter_cache>(inspector);

	if(qualifies() != "")
	{
		sinsp_filter_compiler compiler(inspector, qualifies());
		m_qualifies.reset(compiler.compile());
	}
}

std::string &security_policies::name()
{
	return m_name;
}

uint64_t security_policies::num_loaded_policies()
{
	return m_num_loaded_policies;
}

void security_policies::set_match_details(match_result &match, sinsp_evt *evt)
{
	if(match.effect() == draiosproto::EFFECT_ACCEPT)
	{
		m_metrics->incr(security_evt_metrics::EVM_MATCH_ACCEPT);
	}
	else if(match.effect() == draiosproto::EFFECT_DENY)
	{
		m_metrics->incr(security_evt_metrics::EVM_MATCH_DENY);
	}
	else if(match.effect() == draiosproto::EFFECT_NEXT)
	{
		m_metrics->incr(security_evt_metrics::EVM_MATCH_NEXT);
	}

	match.detail()->mutable_output_details()->set_output_type(match.policies_type());
	if(match.policies_subtype() != draiosproto::PSTYPE_NOSUBTYPE)
	{
		match.detail()->mutable_output_details()->set_output_subtype(match.policies_subtype());
	}
	match.detail()->set_on_default(false);

	std::set<std::string> ofks = { "proc.name", "proc.cmdline" };
	std::set<std::string> default_ofks = default_output_fields_keys(evt);
	ofks.insert(default_ofks.begin(), default_ofks.end());

	//
	// ATM the fields requested from the backend are ignored.
	// Whenever we give users the ability to add "additional"
	// fields in the policy configuration we just have to
	// decomment the following code
	//
	// for(auto ofk: match.output_field_keys())
	// {
	// 	ofks.insert(ofk);
	// }

	for(const auto &ofk: ofks)
	{
		if(ofk != "falco.rule")
		{
			string format{"%" + ofk};
			string res;
			m_formatters->tostring(evt, format, &res);
			(*match.detail()->mutable_output_details()->mutable_output_fields())[ofk] = res;
		}
	}

	if(!match.baseline_id().empty())
	{
		match.detail()->mutable_baseline_details()->set_id(match.baseline_id());
	}
}

void security_policies::set_match_details(match_result &match, json_event *evt)
{
	// TODO @lorenzo - k8s specific metrics
	// if(match.effect() == draiosproto::EFFECT_ACCEPT)
	// {
	// 	m_metrics->incr(security_evt_metrics::EVM_MATCH_ACCEPT);
	// }
	// else if(match.effect() == draiosproto::EFFECT_DENY)
	// {
	// 	m_metrics->incr(security_evt_metrics::EVM_MATCH_DENY);
	// }
	// else if(match.effect() == draiosproto::EFFECT_NEXT)
	// {
	// 	m_metrics->incr(security_evt_metrics::EVM_MATCH_NEXT);
	// }

	match.detail()->mutable_output_details()->set_output_type(match.policies_type());
	if(match.policies_subtype() != draiosproto::PSTYPE_NOSUBTYPE)
	{
		match.detail()->mutable_output_details()->set_output_subtype(match.policies_subtype());
	}
	match.detail()->set_on_default(false);
}

std::string security_policies::qualifies()
{
	return string("");
}

bool security_policies::event_qualifies(sinsp_evt *evt)
{
	if(m_qualifies && !m_qualifies->run(evt))
	{
		m_metrics->incr(security_evt_metrics::EVM_MISS_QUAL);
		return false;
	}

	return true;
}

std::ostream &operator <<(std::ostream &os, const security_policies::match_result &res)
{
	os << res.policy()->name() << ","
	   << (uint32_t) res.policies_type() << ","
	   << (uint32_t) res.policies_subtype() << ","
	   << res.item();

	// Skipping event_detail/match result. This string conversion
	// is only used for debugging of prefix_match trees.

	return os;
}

falco_security_policies::falco_security_policies()
{
	m_name = "falco";
	m_evtsources[ESRC_SINSP] = true;
	m_evtsources[ESRC_K8S_AUDIT] = true;
	// All k8s audit events have the single tag "1". - see falco_engine::process_k8s_audit_event
	m_evttypes[1] = true;
}

falco_security_policies::~falco_security_policies()
{
}

void falco_security_policies::init(dragent_configuration *configuration,
				   sinsp *inspector,
				   std::shared_ptr<security_evt_metrics> metrics)
{
	security_policies::init(configuration, inspector, metrics);
}

void falco_security_policies::set_engine(std::shared_ptr<falco_engine> falco_engine)
{
	m_falco_engine = falco_engine;
}

void falco_security_policies::add_policy(const security_policy &policy, std::shared_ptr<security_baseline> baseline)
{
	if(m_falco_engine && policy.has_falco_details() && policy.enabled())
	{
		// Use the name to create a ruleset. We'll use this
		// ruleset to run only the subset of rules we're
		// interested in.
		string all_rules = ".*";
		string ruleset = policy.name();

		// TODO: if this ruleset is already present, don't do again this initialization

		// We *only* want those rules selected by name/tags, so first disable all rules.
		m_falco_engine->enable_rule(all_rules, false, ruleset);

		if(policy.falco_details().rule_filter().has_name())
		{
			m_falco_engine->enable_rule(policy.falco_details().rule_filter().name(), true, ruleset);
		}

		std::set<string> tags;
		for(auto tag : policy.falco_details().rule_filter().tags())
		{
			tags.insert(tag);
		}

		m_falco_engine->enable_rule_by_tag(tags, true, ruleset);

		m_rulesets.insert(pair<const security_policy *,uint16_t>(&policy, m_falco_engine->find_ruleset_id(ruleset)));

		// Update m_evttypes with all the evttypes used by this ruleset
		vector<bool> evttypes;
		m_falco_engine->evttypes_for_ruleset(evttypes, ruleset);

		for(uint32_t evttype = 0; evttype < PPM_EVENT_MAX; evttype++)
		{
			m_evttypes[evttype] = m_evttypes[evttype] | evttypes[evttype];
		}

		// TODO falco might implement a evtsources_for_ruleset to optimize this out
		vector<bool> evtsources = {false, true, true};

		for(uint32_t evtsource = 0; evtsource < ESRC_MAX; evtsource++)
		{
			m_evtsources[evtsource] = m_evtsources[evtsource] | evtsources[evtsource];
		}

		m_num_loaded_policies++;
	}
}

void falco_security_policies::reset()
{
	m_evttypes.clear();
	m_evtsources.clear();
	m_rulesets.clear();
}

draiosproto::policy_type falco_security_policies::policies_type()
{
	return draiosproto::PTYPE_FALCO;
}

draiosproto::policy_subtype falco_security_policies::policies_subtype()
{
	return draiosproto::PSTYPE_NOSUBTYPE;
}

std::set<std::string> falco_security_policies::default_output_fields_keys(sinsp_evt *evt)
{
	// falco policies handle this internally
	return {};
}

bool falco_security_policies::check_conditions(sinsp_evt *evt)
{
	if(!m_evttypes[evt->get_type()])
	{
		m_metrics->incr(security_evt_metrics::EVM_MISS_FALCO_EVTTYPE);
		return false;
	}

	if(!m_falco_engine)
	{
		m_metrics->incr(security_evt_metrics::EVM_MISS_NO_FALCO_ENGINE);
		return false;
	}

	if((evt->get_info_flags() & EF_DROP_FALCO) != 0)
	{
		m_metrics->incr(security_evt_metrics::EVM_MISS_EF_DROP_FALCO);
		return false;
	}

	return true;
}

bool falco_security_policies::check_conditions(json_event *evt)
{
	if(!m_falco_engine)
	{
		m_metrics->incr(security_evt_metrics::EVM_MISS_NO_FALCO_ENGINE);
		return false;
	}

	return true;
}

security_policies::match_result *falco_security_policies::match_event(sinsp_evt *evt)
{
	if(!check_conditions(evt))
	{
		return NULL;
	}

	match_result *match = NULL;

	for(auto &ruleset : m_rulesets)
	{
		try {
			unique_ptr<falco_engine::rule_result> res = m_falco_engine->process_sinsp_event(evt, ruleset.second);

			if(!res)
			{
				m_metrics->incr(security_evt_metrics::EVM_MISS_CONDS);
			}
			else
			{
				g_log->debug("Event matched falco policy: rule=" + res->rule);

				// This ruleset had a match. We keep
				// it only if its order is less than
				// the current best policy.
				if(!match || ruleset.first->order() < match->policy()->order())
				{
					if(match)
					{
						delete match;
					}

					// We don't need to worry about which rule matched in a given ruleset--falco handles that internally.
					match = new match_result(ruleset.first,
								 policies_type(), policies_subtype(), 0,
								 new draiosproto::event_detail(), draiosproto::EFFECT_DENY,
								 ruleset.first->falco_details().output_field_keys());

					string output;
					m_formatters->tostring(evt, res->format, &output);
					match->detail()->mutable_output_details()->set_output(output);
					(*match->detail()->mutable_output_details()->mutable_output_fields())["falco.rule"] = res->rule;
					map<string,string> rule_output_fields;
					m_formatters->resolve_tokens(evt, res->format, rule_output_fields);
					for(const auto &rof : rule_output_fields)
					{
						(*match->detail()->mutable_output_details()->mutable_output_fields())[rof.first] = rof.second;
					}
					set_match_details(*match, evt);
				}
			}
		}
		catch (falco_exception& e)
		{
			g_log->error("Error processing sinsp event against falco engine: " + string(e.what()));
		}
	}

	return match;
}

security_policies::match_result *falco_security_policies::match_event(json_event *evt)
{
	if(!check_conditions(evt))
	{
		return NULL;
	}

	match_result *match = NULL;
	for(auto &ruleset : m_rulesets)
	{
		try {
			unique_ptr<falco_engine::rule_result> res = m_falco_engine->process_k8s_audit_event(evt, ruleset.second);

			if(!res)
			{
				// TODO @lorenzo - k8s specific metrics
				// m_metrics->incr(security_evt_metrics::EVM_MISS_CONDS);
			}
			else
			{
				g_log->error("Event matched falco policy: rule=" + res->rule);

				// This ruleset had a match. We keep
				// it only if its order is less than
				// the current best policy.
				if(!match || ruleset.first->order() < match->policy()->order())
				{
					if(match)
					{
						delete match;
					}

					// We don't need to worry about which rule matched in a given ruleset--falco handles that internally.
					match = new match_result(ruleset.first,
								 policies_type(), policies_subtype(), 0,
								 new draiosproto::event_detail(), draiosproto::EFFECT_DENY,
								 ruleset.first->falco_details().output_field_keys());

					json_event_formatter jevt_formatter(m_falco_engine->json_factory(), res->format);
					match->detail()->mutable_output_details()->set_output(jevt_formatter.tostring(evt));
					(*match->detail()->mutable_output_details()->mutable_output_fields())["falco.rule"] = res->rule;

					std::list<std::pair<std::string,std::string>> resolved_tokens;
					jevt_formatter.resolve_tokens(evt, resolved_tokens);
					for (const auto &rt : resolved_tokens)
					{
						if (!rt.first.empty() && !rt.second.empty())
							(*match->detail()->mutable_output_details()->mutable_output_fields())[rt.first] = rt.second;
					}

					set_match_details(*match, evt);
				}
			}
		}
		catch (falco_exception& e)
		{
			g_log->error("Error processing k8s audit event against falco engine: " + string(e.what()));
		}
	}

	return match;
}

matchlist_security_policies::matchlist_security_policies()
{
	m_evtsources[ESRC_SINSP] = true;
}

matchlist_security_policies::~matchlist_security_policies()
{

}

void matchlist_security_policies::init(dragent_configuration *configuration,
				       sinsp *inspector,
				       std::shared_ptr<security_evt_metrics> metrics)
{
	security_policies::init(configuration, inspector, metrics);
}

void matchlist_security_policies::add_policy(const security_policy &policy, std::shared_ptr<security_baseline> baseline)
{
	bool added = false;

	if(policy.has_matchlist_details())
	{
		added |= add_matchlist_details(policy, policy.matchlist_details());
	}

	if(baseline && is_baseline_requested(policy)) {
		added |= add_matchlist_details(policy, baseline->matchlist_details(), baseline->id());
	}

	if(added)
	{
		m_num_loaded_policies++;
	}
}

void matchlist_security_policies::reset()
{
}

void matchlist_security_policies::add_default_match_result(match_result &res)
{
	// This keeps the minimum non-NEXT default match result
	if(res.effect() != draiosproto::EFFECT_NEXT)
	{
		if(!m_default_match.policy() || match_result::compare(res, m_default_match))
		{
			// Note: shallow copy. Assuming detail is NULL or can be
			// shallowly copied.
			m_default_match = res;
		}
	}
}

security_policies::match_result * matchlist_security_policies::min_default_match(sinsp_evt *evt)
{
	match_result *match = NULL;

	m_metrics->incr(security_evt_metrics::EVM_MISS_CONDS);

	if(m_default_match.policy())
	{
		match = new match_result(m_default_match.policy(),
					 policies_type(),
					 policies_subtype(),
					 m_default_match.item(),
					 new draiosproto::event_detail(),
					 m_default_match.effect(),
					 m_default_match.output_field_keys(),
					 m_default_match.baseline_id());

		set_match_details(*match, evt);
		match->detail()->set_on_default(true);

		if(g_logger.get_severity() >= sinsp_logger::SEV_TRACE)
		{
			g_log->trace("Event matched default effect of " + name() +
				     " policy: " + match->policy()->name() +
				     " details: " + match->detail()->DebugString() +
				     " effect: " + draiosproto::match_effect_Name(match->effect()));
		}
	}

	return match;
}

filtercheck_policies::filtercheck_policies()
{
}

filtercheck_policies::~filtercheck_policies()
{

}

void filtercheck_policies::init(dragent_configuration *configuration,
				sinsp *inspector,
				std::shared_ptr<security_evt_metrics> metrics)
{
	matchlist_security_policies::init(configuration, inspector, metrics);
}

void filtercheck_policies::reset()
{
	matchlist_security_policies::reset();

	m_index.clear();
	m_val_storages.clear();
}

filter_value_t filtercheck_policies::add_filter_value(uint8_t *val, uint32_t len)
{
	m_val_storages.push_back(vector<uint8_t>(len));
	memcpy(&m_val_storages[m_val_storages.size()-1][0], val, len);

	return filter_value_t(&m_val_storages[m_val_storages.size()-1][0], len);
}

security_policies::match_result *filtercheck_policies::match_event(sinsp_evt *evt)
{
	if(!event_qualifies(evt))
	{
		return NULL;
	}

	uint8_t *val;
	uint32_t len;
	val = m_check->extract(evt, &len);

	if(!val)
	{
		m_metrics->incr(security_evt_metrics::EVM_MISS_CONDS);
		return NULL;
	}

	filter_value_t key(val, len);

	auto matches = m_index.equal_range(key);

	if(matches.first == matches.second)
	{
		return min_default_match(evt);
	}

	auto comp = [evt, this] (const std::pair<filter_value_t, security_policies::match_result> &a,
				 const std::pair<filter_value_t, security_policies::match_result> &b)
	{
		return security_policies::match_result::compare(a.second, b.second);
	};

	auto it = std::min_element(matches.first, matches.second, comp);

	match_result *match = new match_result(it->second.policy(),
					       policies_type(),
					       policies_subtype(),
					       it->second.item(),
					       new draiosproto::event_detail(),
					       it->second.effect(),
					       it->second.output_field_keys(),
					       it->second.baseline_id());
	set_match_details(*match, evt);

	return match;
}

net_inbound_policies::net_inbound_policies()
{
	m_name = "network-inbound";

	m_evttypes[PPME_SOCKET_ACCEPT_X] = true;
	m_evttypes[PPME_SOCKET_ACCEPT4_X] = true;
	m_evttypes[PPME_SOCKET_ACCEPT_5_X] = true;
	m_evttypes[PPME_SOCKET_ACCEPT4_5_X] = true;
	m_evttypes[PPME_SOCKET_RECVFROM_X] = true;
	m_evttypes[PPME_SOCKET_RECVMSG_X] = true;
}

net_inbound_policies::~net_inbound_policies()
{
}

void net_inbound_policies::init(dragent_configuration *configuration,
				sinsp *inspector,
				std::shared_ptr<security_evt_metrics> metrics)
{
	matchlist_security_policies::init(configuration, inspector, metrics);
}

void net_inbound_policies::reset()
{
	m_index.clear();
}

draiosproto::policy_type net_inbound_policies::policies_type()
{
	return draiosproto::PTYPE_NETWORK;
}

draiosproto::policy_subtype net_inbound_policies::policies_subtype()
{
	return draiosproto::PSTYPE_NETWORK_INBOUND;
}

std::set<std::string> net_inbound_policies::default_output_fields_keys(sinsp_evt *evt)
{
	return { "fd.l4proto", "fd.cip", "fd.cport", "fd.sip", "fd.sport" };
}

std::string net_inbound_policies::qualifies()
{
	return string("((evt.type = accept and evt.dir=<) or "
		      " (evt.type in (recvfrom,recvmsg) and evt.dir=< and "
		      "  fd.l4proto != tcp and fd.connected=false and fd.name_changed=true)) and "
		      "(fd.typechar = 4 or fd.typechar = 6) and "
		      "(fd.ip != 0.0.0.0 and fd.net != 127.0.0.0/8) and "
		      "(evt.rawres >= 0 or evt.res = EINPROGRESS)"
		);
}

bool net_inbound_policies::add_matchlist_details(const security_policy &policy,
						 const draiosproto::matchlist_detail &details,
						 std::string baseline_id)
{
	bool added = false;

	if((policies_subtype() == draiosproto::PSTYPE_NETWORK_INBOUND && !details.has_inbound_details()) ||
	   (policies_subtype() == draiosproto::PSTYPE_NETWORK_OUTBOUND && !details.has_outbound_details()))
	{
		return added;
	}

	const auto &sdetails = policies_subtype() == draiosproto::PSTYPE_NETWORK_INBOUND ?
		details.inbound_details() : details.outbound_details();

	if(sdetails.on_default() == draiosproto::EFFECT_NEXT)
	{
		return added;
	}

	match_result res(
		&policy,
		policies_type(),
		policies_subtype(),
		0,
		NULL,
		sdetails.on_default(),
		sdetails.output_field_keys(),
		baseline_id);
	m_index.insert(std::upper_bound(m_index.begin(),
					m_index.end(),
					res,
					security_policies::match_result::compare),
		       res);
	added = true;

	return added;
}

security_policies::match_result *net_inbound_policies::match_event(sinsp_evt *evt)
{
	if(!event_qualifies(evt))
	{
		return NULL;
	}

	const match_result *best_match = NULL;
	for(const auto &m : m_index)
	{
		best_match = &m;
		break;
	}

	if(!best_match)
	{
		return NULL;
	}

	match_result *match = new match_result(best_match->policy(),
					       policies_type(),
					       policies_subtype(),
					       best_match->item(),
					       new draiosproto::event_detail(),
					       best_match->effect(),
					       best_match->output_field_keys(),
					       best_match->baseline_id());
	set_match_details(*match, evt);

	return match;
}

net_outbound_policies::net_outbound_policies()
{
	m_name = "network-outbound";

	m_evttypes.assign(PPM_EVENT_MAX+1, false);
	m_evttypes[PPME_SOCKET_CONNECT_X] = true;
	m_evttypes[PPME_SOCKET_SENDTO_X] = true;
	m_evttypes[PPME_SOCKET_SENDMSG_X] = true;
}

net_outbound_policies::~net_outbound_policies()
{
}

draiosproto::policy_type net_outbound_policies::policies_type()
{
	return draiosproto::PTYPE_NETWORK;
}

draiosproto::policy_subtype net_outbound_policies::policies_subtype()
{
	return draiosproto::PSTYPE_NETWORK_OUTBOUND;
}

std::string net_outbound_policies::qualifies()
{
	return string("((evt.type = connect and evt.dir=<) or "
		      " (evt.type in (sendto,sendmsg) and evt.dir=< and "
		      "  fd.l4proto != tcp and fd.connected=false and fd.name_changed=true)) and "
		      "(fd.typechar = 4 or fd.typechar = 6) and "
		      "(fd.ip != 0.0.0.0 and fd.net != 127.0.0.0/8) and "
		      "(evt.rawres >= 0 or evt.res = EINPROGRESS)"
		);
}

tcp_listenport_policies::tcp_listenport_policies()
{
	m_name = "listenports-tcp";

	m_evttypes[PPME_SOCKET_LISTEN_E] = true;

	m_proto = draiosproto::PROTO_TCP;
}

tcp_listenport_policies::~tcp_listenport_policies()
{
}

void tcp_listenport_policies::init(dragent_configuration *configuration,
				   sinsp *inspector,
				   std::shared_ptr<security_evt_metrics> metrics)
{
	filtercheck_policies::init(configuration, inspector, metrics);

	m_check.reset(g_filterlist.new_filter_check_from_fldname("fd.sport", m_inspector, true));
	m_check->parse_field_name("fd.sport", true, false);
}

draiosproto::policy_type tcp_listenport_policies::policies_type()
{
	return draiosproto::PTYPE_NETWORK;
}

draiosproto::policy_subtype tcp_listenport_policies::policies_subtype()
{
	return draiosproto::PSTYPE_NETWORK_LISTENING;
}

std::set<std::string> tcp_listenport_policies::default_output_fields_keys(sinsp_evt *evt)
{
	return { "fd.l4proto", "fd.sip", "fd.sport" };
}

std::string tcp_listenport_policies::qualifies()
{
	return string("fd.l4proto = tcp");
}

bool tcp_listenport_policies::add_matchlist_details(const security_policy &policy,
						    const draiosproto::matchlist_detail &details,
						    std::string baseline_id)
{
	bool added = false;

	if(details.has_listenport_details())
	{
		uint32_t item = 0;
		for(auto &match_list : details.listenport_details().lists())
		{
			item++;
			if(match_list.proto() == m_proto)
			{
				for(auto &portstr : match_list.values())
				{
					uint16_t port = (uint16_t) strtoul(portstr.c_str(), NULL, 10);

					filter_value_t key = add_filter_value((uint8_t *) &port, sizeof(uint16_t));
					m_index.emplace(std::make_pair(key,
								       match_result(
									       &policy,
									       policies_type(),
									       policies_subtype(),
									       item,
									       NULL,
									       match_list.on_match(),
									       details.listenport_details().output_field_keys(),
									       baseline_id)));
				}
			}
		}
		added = true;
		if(details.listenport_details().on_default() != draiosproto::EFFECT_NEXT)
		{
			match_result res(&policy,
					 policies_type(),
					 policies_subtype(),
					 0,
					 NULL,
					 details.listenport_details().on_default(),
					 details.listenport_details().output_field_keys(),
					 baseline_id);
			add_default_match_result(res);
		}
	}

	return added;
}

udp_listenport_policies::udp_listenport_policies()
{
	m_name = "listenports-udp";

	m_evttypes.assign(PPM_EVENT_MAX+1, false);
	m_evttypes[PPME_SOCKET_RECVFROM_E] = true;
	m_evttypes[PPME_SOCKET_RECVMSG_E] = true;

	m_proto = draiosproto::PROTO_UDP;
}

udp_listenport_policies::~udp_listenport_policies()
{
}

std::string udp_listenport_policies::qualifies()
{
	return string("fd.l4proto = udp and fd.connected = false");
}

syscall_policies::syscall_policies()
{
	m_name = "syscalls";

	for(uint32_t j = 0; j < PPM_EVENT_MAX; j++)
	{
		if(PPME_IS_ENTER(j))
		{
			m_evttypes[j] = true;
		}
	}
}

syscall_policies::~syscall_policies()
{
}

void syscall_policies::init(dragent_configuration *configuration,
			    sinsp *inspector,
			    std::shared_ptr<security_evt_metrics> metrics)
{
	matchlist_security_policies::init(configuration, inspector, metrics);

	// Create a table containing all events, so they can
	// be mapped to event ids.
	sinsp_evttables* einfo = m_inspector->get_event_info_tables();
	m_etable = einfo->m_event_info;
	m_stable = einfo->m_syscall_info_table;

	for(uint32_t j = 0; j < PPM_EVENT_MAX; j++)
	{
		if(PPME_IS_ENTER(j))
		{
			auto it = m_evtnums.lower_bound(m_etable[j].name);

			if (it == m_evtnums.end() ||
			    it->first != m_etable[j].name)
			{
				it = m_evtnums.emplace_hint(it, std::make_pair(m_etable[j].name, std::list<uint32_t>()));
			}

			it->second.push_back(j);
		}
	}

	for(uint32_t j = 0; j < PPM_SC_MAX; j++)
	{
		m_syscallnums.insert(make_pair(m_stable[j].name, j));
	}
}

void syscall_policies::reset()
{
	matchlist_security_policies::reset();

	m_event_index.clear();
	m_event_index.resize(PPM_EVENT_MAX+1);

	m_syscall_index.clear();
	m_syscall_index.resize(PPM_SC_MAX+1);
}

draiosproto::policy_type syscall_policies::policies_type()
{
	return draiosproto::PTYPE_SYSCALL;
}

draiosproto::policy_subtype syscall_policies::policies_subtype()
{
	return draiosproto::PSTYPE_NOSUBTYPE;
}

std::set<std::string> syscall_policies::default_output_fields_keys(sinsp_evt *evt)
{
	return { "evt.type" };
}

bool syscall_policies::event_qualifies(sinsp_evt *evt)
{
	return evt->falco_consider();
}

bool syscall_policies::add_matchlist_details(const security_policy &policy,
					     const draiosproto::matchlist_detail &details,
					     std::string baseline_id)
{
	bool added = false;

	if(details.has_syscall_details())
	{
		uint32_t item = 0;
		for(auto &match_list : details.syscall_details().lists())
		{
			item++;
			for(auto &evtstr : match_list.values())
			{
				auto it = m_evtnums.find(evtstr);

				if(it != m_evtnums.end())
				{
					for (auto evtnum : it->second)
					{
						if(!sinsp::falco_consider_evtnum(evtnum))
						{
							continue;
						}

						// Insert into the list for this event
						// number in policy order order. That
						// way we can just traverse the list
						// of match results for a given event
						// until we find a terminal action.
						match_result res(&policy,
								 policies_type(),
								 policies_subtype(),
								 item,
								 NULL,
								 match_list.on_match(),
								 details.syscall_details().output_field_keys(),
								 baseline_id);
						m_event_index[evtnum].insert(std::upper_bound(m_event_index[evtnum].begin(),
											      m_event_index[evtnum].end(),
											      res,
											      security_policies::match_result::compare),
									     res);
					}
				}

				auto it2 = m_syscallnums.find(evtstr);

				if(it2 != m_syscallnums.end())
				{
					if(sinsp::falco_consider_syscallid(it2->second)) {
						match_result res(&policy,
								 policies_type(),
								 policies_subtype(),
								 item,
								 NULL,
								 match_list.on_match(),
								 details.syscall_details().output_field_keys(),
								 baseline_id);
						m_syscall_index[it2->second].insert(std::upper_bound(m_syscall_index[it2->second].begin(),
												     m_syscall_index[it2->second].end(),
												     res,
												     security_policies::match_result::compare),
										    res);
					}
				}
			}
		}
		if(details.syscall_details().on_default() != draiosproto::EFFECT_NEXT)
		{
			match_result res(&policy,
					 policies_type(),
					 policies_subtype(),
					 0,
					 NULL,
					 details.syscall_details().on_default(),
					 details.syscall_details().output_field_keys(),
					 baseline_id);
			add_default_match_result(res);
		}
		added = true;
	}

	return added;
}

security_policies::match_result *syscall_policies::match_event(sinsp_evt *evt)
{
	match_result *best_match = NULL;
	uint16_t etype = evt->get_type();

	if(!event_qualifies(evt))
	{
		return NULL;
	}

	if(etype == PPME_GENERIC_E || etype == PPME_GENERIC_X)
	{
		sinsp_evt_param *parinfo = evt->get_param(0);
		ASSERT(parinfo->m_len == sizeof(uint16_t));
		uint16_t evid = *(uint16_t *)parinfo->m_val;

		for(auto &res : m_syscall_index[evid])
		{
			best_match = &res;
			if(res.effect() != draiosproto::EFFECT_NEXT)
			{
				break;
			}
		}

	}
	else
	{
		for(auto &res : m_event_index[etype])
		{
			best_match = &res;
			if(res.effect() != draiosproto::EFFECT_NEXT)
			{
				break;
			}
		}
	}

	if(!best_match)
	{
		return min_default_match(evt);
	}

	match_result *match = new match_result(best_match->policy(),
					       policies_type(),
					       policies_subtype(),
					       best_match->item(),
					       new draiosproto::event_detail(),
					       best_match->effect(),
					       best_match->output_field_keys(),
					       best_match->baseline_id());
	set_match_details(*match, evt);
	return match;
}

matchlist_map_security_policies::matchlist_map_security_policies()
{
	m_empty_lists.set_on_default(draiosproto::EFFECT_NEXT);
}

matchlist_map_security_policies::~matchlist_map_security_policies()
{
}

void matchlist_map_security_policies::init(dragent_configuration *configuration,
					   sinsp *inspector,
					   std::shared_ptr<security_evt_metrics> metrics)
{
	matchlist_security_policies::init(configuration, inspector, metrics);
}

void matchlist_map_security_policies::reset()
{
	matchlist_security_policies::reset();

	m_vals.clear();
	m_index.clear();

	// The vector is indexed by match effect as a number
	// (0=ACCEPT, 1=DENY, 2=NEXT), so add 3 elements.
	m_index.push_back(path_matchresult_search());
	m_index.push_back(path_matchresult_search());
	m_index.push_back(path_matchresult_search());
}

security_policies::match_result *matchlist_map_security_policies::match_event(sinsp_evt *evt)
{
	if(!event_qualifies(evt))
	{
		return NULL;
	}

	auto range = m_checks.equal_range(evt->get_type());

	for(auto it = range.first; it != range.second; ++it)
	{
		uint8_t *val;
		uint32_t len;

		val = it->second->extract(evt, &len);

		if(!val)
		{
			m_metrics->incr(security_evt_metrics::EVM_MISS_CONDS);
			return NULL;
		}

		filter_value_t key(val, len);
		filter_components_t components;

		split_components(key, components);

		const match_result *best_match = NULL;

		// Loop over the 3 prefix_map objects (for
		// ACCEPT, DENY, NEXT). Find the best
		// match_result that matches the path and
		// return it.
		for(auto &prefix_map : m_index)
		{
			const match_result *found = NULL;
			if((found = prefix_map.match_components(components)) != NULL)
			{
				if(best_match == NULL ||
				   match_result::compare_ptr(found, best_match))
				{
					best_match = found;
				}
			}
		}

		if(!best_match)
		{
			continue;
		}

		match_result *match = new match_result(best_match->policy(),
						       policies_type(),
						       policies_subtype(),
						       best_match->item(),
						       new draiosproto::event_detail(),
						       best_match->effect(),
						       best_match->output_field_keys(),
						       best_match->baseline_id());
		set_match_details(*match, evt);

		return match;
	}

	return min_default_match(evt);
}

bool matchlist_map_security_policies::add_matchlist_details(const security_policy &policy,
							    const draiosproto::matchlist_detail &details,
							    std::string baseline_id)
{
	bool added = false;
	uint32_t item = 0;

	const draiosproto::match_lists &lists = get_match_lists(details);

	for(auto &match_list : lists.lists())
	{
		item++;
		added = true;

		if(match_list_relevant(match_list))
		{
			for(auto &val : match_list.values())
			{
				m_vals.push_back(val);
				filter_value_t key = make_pair((uint8_t *) m_vals.back().c_str(), m_vals.back().length());

				path_matchresult_search &search = m_index[(uint32_t) match_list.on_match()-1];

				filter_components_t components;
				split_components(key, components);

				match_result res(&policy,
						 policies_type(),
						 policies_subtype(),
						 item,
						 NULL,
						 match_list.on_match(),
						 lists.output_field_keys(),
						 baseline_id);

				// Don't need to allocate this, prefix_search_map
				// makes its own copy.
				search.add_search_path_components(components, res);
			}
		}
	}

	if(lists.on_default()!= draiosproto::EFFECT_NEXT)
	{
		match_result res(&policy,
				 policies_type(),
				 policies_subtype(),
				 0,
				 NULL,
				 lists.on_default(),
				 lists.output_field_keys(),
				 baseline_id);
		add_default_match_result(res);
	}

	return added;
}

bool matchlist_map_security_policies::match_list_relevant(const draiosproto::match_list &list)
{
	return true;
}

readonly_fs_policies::readonly_fs_policies()
{
	m_name = "files-readonly";

	m_evttypes[PPME_SYSCALL_OPEN_X] = true;
	m_evttypes[PPME_SYSCALL_OPENAT_2_X] = true;

	m_access_type = draiosproto::ACCESS_READ;
}

readonly_fs_policies::~readonly_fs_policies()
{
}

void readonly_fs_policies::init(dragent_configuration *configuration,
				sinsp *inspector,
				std::shared_ptr<security_evt_metrics> metrics)
{
	matchlist_map_security_policies::init(configuration, inspector, metrics);

	std::shared_ptr<sinsp_filter_check> fdn;
	fdn.reset(g_filterlist.new_filter_check_from_fldname("fd.name", m_inspector, true));
	fdn->parse_field_name("fd.name", true, false);
	m_checks.emplace(PPME_SYSCALL_OPEN_X, fdn);
	m_checks.emplace(PPME_SYSCALL_OPENAT_2_X, fdn);
}

draiosproto::policy_type readonly_fs_policies::policies_type()
{
	return draiosproto::PTYPE_FILESYSTEM;
}

draiosproto::policy_subtype readonly_fs_policies::policies_subtype()
{
	return draiosproto::PSTYPE_FILESYSTEM_READ;
}

std::set<std::string> readonly_fs_policies::default_output_fields_keys(sinsp_evt *evt)
{
	return { "evt.type", "fd.name" };
}

std::string readonly_fs_policies::qualifies()
{
	return string("evt.rawres > 0 and evt.is_open_read=true and evt.is_open_write=false");
}

void readonly_fs_policies::split_components(const filter_value_t &val, filter_components_t &components)
{
	split_path(val, components);
	// Add an initial "root" to the set of components. That
	// ensures that a top-level path of '/' still results in a
	// non-empty components list. For all other paths, there will
	// be a dummy 'root' prefix at the top of every path.
	components.emplace_front((uint8_t *) "root", 4);
}

const draiosproto::match_lists &readonly_fs_policies::get_match_lists(const draiosproto::matchlist_detail &details)
{
	return (details.has_fs_details() ? details.fs_details() : m_empty_lists);
}

bool readonly_fs_policies::match_list_relevant(const draiosproto::match_list &list)
{
	return (list.fs_access_type() == m_access_type);
}

readwrite_fs_policies::readwrite_fs_policies()
{
	m_name = "files-readwrite";
	m_access_type = draiosproto::ACCESS_WRITE;
}

readwrite_fs_policies::~readwrite_fs_policies()
{
}

draiosproto::policy_subtype readwrite_fs_policies::policies_subtype()
{
	return draiosproto::PSTYPE_FILESYSTEM_READWRITE;
}

std::string readwrite_fs_policies::qualifies()
{
	return string("evt.rawres > 0 and evt.is_open_write=true");
}

nofd_readwrite_fs_policies::nofd_readwrite_fs_policies()
{
	m_name = "files-readwrite-nofd";

	m_evttypes.assign(PPM_EVENT_MAX+1, false);
	m_evttypes[PPME_SYSCALL_MKDIR_2_X] = true;
	m_evttypes[PPME_SYSCALL_MKDIRAT_X] = true;
	m_evttypes[PPME_SYSCALL_RMDIR_2_X] = true;
	m_evttypes[PPME_SYSCALL_RENAME_X] = true;
	m_evttypes[PPME_SYSCALL_RENAMEAT_X] = true;
	m_evttypes[PPME_SYSCALL_UNLINK_2_X] = true;
	m_evttypes[PPME_SYSCALL_UNLINKAT_2_X] = true;
}

nofd_readwrite_fs_policies::~nofd_readwrite_fs_policies()
{
}

void nofd_readwrite_fs_policies::init(dragent_configuration *configuration,
				      sinsp *inspector,
				      std::shared_ptr<security_evt_metrics> metrics)
{
	matchlist_map_security_policies::init(configuration, inspector, metrics);

	std::shared_ptr<sinsp_filter_check> arg1, arg2, absp, absdst;
	arg1.reset(g_filterlist.new_filter_check_from_fldname("evt.arg[1]", m_inspector, true));
	arg1->parse_field_name("evt.arg[1]", true, false);
	arg2.reset(g_filterlist.new_filter_check_from_fldname("evt.arg[2]", m_inspector, true));
	arg2->parse_field_name("evt.arg[2]", true, false);
	absp.reset(g_filterlist.new_filter_check_from_fldname("evt.abspath", m_inspector, false));
	absp->parse_field_name("evt.abspath", true, false);
	absdst.reset(g_filterlist.new_filter_check_from_fldname("evt.abspath.dst", m_inspector, false));
	absdst->parse_field_name("evt.abspath.dst", true, false);

	m_checks.emplace(PPME_SYSCALL_MKDIR_2_X, arg1);
	m_checks.emplace(PPME_SYSCALL_RMDIR_2_X, arg1);
	m_checks.emplace(PPME_SYSCALL_UNLINK_2_X, arg1);
	m_checks.emplace(PPME_SYSCALL_RENAME_X, arg1);

	m_checks.emplace(PPME_SYSCALL_MKDIRAT_X, absp);
	m_checks.emplace(PPME_SYSCALL_UNLINKAT_2_X, absp);
	m_checks.emplace(PPME_SYSCALL_RENAMEAT_X, absp);

	m_checks.emplace(PPME_SYSCALL_RENAME_X, arg2);

	m_checks.emplace(PPME_SYSCALL_RENAMEAT_X, absdst);
}

std::set<std::string> nofd_readwrite_fs_policies::default_output_fields_keys(sinsp_evt *evt)
{
       switch(evt->get_type())
       {
       case PPME_SYSCALL_MKDIR_2_X:
       case PPME_SYSCALL_RMDIR_2_X:
       case PPME_SYSCALL_UNLINK_2_X:
               return { "evt.type", "evt.arg[1]" };
       case PPME_SYSCALL_RENAME_X:
               return { "evt.type", "evt.arg[1]", "evt.arg[2]" };
       case PPME_SYSCALL_MKDIRAT_X:
       case PPME_SYSCALL_UNLINKAT_2_X:
               return { "evt.type", "evt.abspath" };
       case PPME_SYSCALL_RENAMEAT_X:
               return { "evt.type", "evt.abspath", "evt.abspath.dst" };
       default:
               return { "evt.type" };
       }
}

std::string nofd_readwrite_fs_policies::qualifies()
{
	return string("evt.rawres = 0");
}

container_policies::container_policies()
{
	m_name = "containers";

	m_evttypes[PPME_SYSCALL_EXECVE_18_X] = true;
	m_evttypes[PPME_SYSCALL_EXECVE_19_X] = true;
}

container_policies::~container_policies()
{
}

void container_policies::init(dragent_configuration *configuration,
			      sinsp *inspector,
			      std::shared_ptr<security_evt_metrics> metrics)
{
	matchlist_security_policies::init(configuration, inspector, metrics);

	std::shared_ptr<sinsp_filter_check> cim;
	cim.reset(g_filterlist.new_filter_check_from_fldname("container.image", m_inspector, true));
	cim->parse_field_name("container.image", true, false);
	m_checks.emplace(PPME_SYSCALL_EXECVE_18_X, cim);
	m_checks.emplace(PPME_SYSCALL_EXECVE_19_X, cim);
}

draiosproto::policy_type container_policies::policies_type()
{
	return draiosproto::PTYPE_CONTAINER;
}

draiosproto::policy_subtype container_policies::policies_subtype()
{
	return draiosproto::PSTYPE_NOSUBTYPE;
}

std::set<std::string> container_policies::default_output_fields_keys(sinsp_evt *evt)
{
	return { "container.id", "container.name", "container.image", "container.image.id" };
}

std::string container_policies::qualifies()
{
	return string("proc.vpid=1 and container.id != host");
}

void container_policies::split_components(const filter_value_t &val, filter_components_t &components)
{
	// Regex: (we can switch to it if we will ever support gcc 4.9+)
	// ^(?:((?=[^:]{4,253})[a-zA-Z0-9-]{1,63}(?:[.][a-zA-Z0-9-]{1,63})*)(?::?([0-9]{1,5}))?/)? -> host.name:port/
	// ((?:[a-z0-9._-])*(?:/[a-z0-9._-]*)*)(?::((?![.-])[a-zA-Z0-9_.-]{1,128}))? ---------------> name:tag
	// (?:@[A-Za-z][A-Za-z0-9]*(?:[-_+.][A-Za-z][A-Za-z0-9]*)*:([0-9A-Fa-f]{32,}))?$ -----------> @digest

	std::string h, p, n, t, d, image = string((const char *)val.first);

	sinsp_utils::split_container_image(image, h, p, n, t, d);

	filter_value_t empty = {(uint8_t *) "\0", 1};
	std::list<std::string> l = {h, p, n, t, d};
	size_t lastpos = 0;
	for(const auto &c : l)
	{
		if(c.empty())
		{
			components.emplace_back(empty);
		}
		else
		{
			lastpos = image.find(c, lastpos);
			components.emplace_back(make_pair((uint8_t *)(val.first + lastpos), c.length()));
		}
	}

	g_equal_to_membuf filter_value_equal;
	while(filter_value_equal(components.back(), empty))
	{
		components.pop_back();
	}
}

const draiosproto::match_lists &container_policies::get_match_lists(const draiosproto::matchlist_detail &details)
{
	return (details.has_container_details() ? details.container_details() : m_empty_lists);
}

process_policies::process_policies()
{
	m_name = "processes";

	m_evttypes[PPME_SYSCALL_EXECVE_18_X] = true;
	m_evttypes[PPME_SYSCALL_EXECVE_19_X] = true;
}

process_policies::~process_policies()
{
}

void process_policies::init(dragent_configuration *configuration,
			    sinsp *inspector,
			    std::shared_ptr<security_evt_metrics> metrics)
{
	filtercheck_policies::init(configuration, inspector, metrics);

	m_check.reset(g_filterlist.new_filter_check_from_fldname("proc.name", m_inspector, true));
	m_check->parse_field_name("proc.name", true, false);
}

draiosproto::policy_type process_policies::policies_type()
{
	return draiosproto::PTYPE_PROCESS;
}

draiosproto::policy_subtype process_policies::policies_subtype()
{
	return draiosproto::PSTYPE_NOSUBTYPE;
}

std::set<std::string> process_policies::default_output_fields_keys(sinsp_evt *evt)
{
	return { "proc.name" };
}

bool process_policies::add_matchlist_details(const security_policy &policy,
                                             const draiosproto::matchlist_detail &details,
					     std::string baseline_id)
{
	bool added = false;

	if(details.has_process_details())
	{
		uint32_t item = 0;
		for(auto &match_list : details.process_details().lists())
		{
			for(auto &pname : match_list.values())
			{
				item++;
				filter_value_t key = add_filter_value((uint8_t *) pname.c_str(), pname.length());
				m_index.emplace(std::make_pair(key,
							       match_result(&policy,
									    policies_type(),
									    policies_subtype(),
									    item,
									    NULL,
									    match_list.on_match(),
									    details.process_details().output_field_keys(),
									    baseline_id)));
			}
		}
		if(details.process_details().on_default() != draiosproto::EFFECT_NEXT)
		{
			match_result res(&policy,
					 policies_type(),
					 policies_subtype(),
					 0,
					 NULL,
					 details.process_details().on_default(),
					 details.process_details().output_field_keys(),
					 baseline_id);
			add_default_match_result(res);
		}
		added = true;
	}

	return added;
}
#endif // CYGWING_AGENT
