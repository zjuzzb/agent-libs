#ifndef CYGWING_AGENT
#include <string>
#include <memory>

#include "logger.h"
#include "json_evt.h"

#include "security_mgr.h"
#include "security_rule.h"

extern sinsp_filter_check_list g_filterlist;

using namespace std;
using namespace path_prefix_map_ut;

security_policy_v2::security_policy_v2(const draiosproto::policy_v2 &policy_v2)
	: draiosproto::policy_v2(policy_v2)
{
}

security_policy_v2::~security_policy_v2()
{
}

bool security_policy_v2::has_action(const draiosproto::action_type &atype)
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

bool security_policy_v2::match_scope(std::string container_id, sinsp_analyzer *analyzer) const
{
	::scope_predicates empty_preds;

	if(!analyzer)
	{
		return true;
	}

	infrastructure_state::uid_t uid;
	if (!container_id.empty())
	{
		uid = make_pair("container", container_id);
	} else
	{
		uid = make_pair("host", analyzer->get_configuration_read_only()->get_machine_id());
	}

	// The way to express "run only on hosts and not in
	// containers" is 'container.id = ""'. However,
	// infrastrucure state doesn't know of a container with the id
	// "". So if the only scope predicate is "container.id = "",
	// ensure that the container id is empty. If it is,
	// continue to checking with infra state but use an empty set
	// of predicates.  If the container id is not empty, return
	// false.
	bool host_only_scope = false;

	if(scope_predicates().size() == 1)
	{
		const draiosproto::scope_predicate &pred = scope_predicates()[0];

		if (pred.key() == "container.id" &&
		    pred.op() == draiosproto::EQ &&
		    pred.values().size() == 1 &&
		    pred.values()[0] == "")
		{
			host_only_scope = true;
			if(container_id != "")
			{
				return false;
			}
		}
	}

	return scope_predicates().empty() ||
		analyzer->infra_state()->match_scope(uid, (host_only_scope ? empty_preds : scope_predicates()));
}

security_rule_library::rule::rule(const std::string &name, draiosproto::policy_type rule_type)
	: m_name(name),
	  m_rule_type(rule_type)
{
}

security_rule_library::rule::~rule()
{
}

std::string &security_rule_library::rule::name()
{
	return m_name;
}

draiosproto::policy_type security_rule_library::rule::rule_type()
{
	return m_rule_type;
}

std::ostream &operator <<(std::ostream &os, const security_rule_library::rule::match_list &ml)
{
	os << "[";

	for(auto &item : ml.m_items)
	{
		os << " " << item;
	}

	os << " ]";

	return os;
}

std::string security_rule_library::rule::as_string()
{
	ostringstream os;

	os << "Name: " << m_name << " type= " << m_rule_type;

	switch(m_rule_type)
	{
	case draiosproto::PTYPE_PROCESS:
		os << " Processes: " << get_process_details()->m_processes;
		break;
	case draiosproto::PTYPE_FILESYSTEM:
		os << " Read-write paths: " << get_filesystem_details()->m_readwrite_paths;
		os << " Read-only paths: " << get_filesystem_details()->m_readonly_paths;
		break;
	case draiosproto::PTYPE_SYSCALL:
		os << " Syscalls: " << get_syscall_details()->m_syscalls;
		break;
	case draiosproto::PTYPE_CONTAINER:
		os << " Containers: " << get_container_details()->m_containers;
		break;
	case draiosproto::PTYPE_NETWORK:
		os << " All inbound= " << get_network_details()->m_all_inbound;
		os << " All outbound= " << get_network_details()->m_all_outbound;
		os << " TCP Listenports: " << get_network_details()->m_tcp_listen_ports;
		os << " UDP Listenports: " << get_network_details()->m_udp_listen_ports;
		break;

	case draiosproto::PTYPE_FALCO:
	default:
		// Can't have fastengine falco rules.
		break;
	}

	return os.str();
}

const security_rule_library::rule::process_details *security_rule_library::rule::get_process_details()
{
	return m_process_details.get();
}

const security_rule_library::rule::filesystem_details *security_rule_library::rule::get_filesystem_details()
{
	return m_filesystem_details.get();
}

const security_rule_library::rule::syscall_details *security_rule_library::rule::get_syscall_details()
{
	return m_syscall_details.get();
}

const security_rule_library::rule::container_details *security_rule_library::rule::get_container_details()
{
	return m_container_details.get();
}

const security_rule_library::rule::network_details *security_rule_library::rule::get_network_details()
{
	return m_network_details.get();
}

bool security_rule_library::rule::parse_matchlist(struct match_list &list,
						  const Json::Value &val)
{
	if(val.isNull() ||
	   !val.isObject() ||
	   !val.isMember("items") ||
	   !val["items"].isArray() ||
	   !val.isMember("matchItems") ||
	   !val["matchItems"].isConvertibleTo(Json::booleanValue))
	{
		return false;
	}

	for(uint32_t i=0; i<val["items"].size(); i++)
	{
		const Json::Value &item = val["items"][i];

		list.m_items.insert(item.asString());
	}

	list.m_match_items = val["matchItems"].asBool();

	return true;
}

bool security_rule_library::rule::parse_process_details(const Json::Value &val)
{
	if(!val.isMember("processes"))
	{
		return false;
	}

	m_process_details = std::unique_ptr<process_details>(new process_details());

	return parse_matchlist(m_process_details->m_processes,
			      val["processes"]);
}

bool security_rule_library::rule::parse_filesystem_details(const Json::Value &val)
{
	if(!val.isMember("readWritePaths") &&
	   !val.isMember("readPaths"))
	{
		return false;
	}

	m_filesystem_details = std::unique_ptr<filesystem_details>(new filesystem_details());

	if(val.isMember("readWritePaths"))
	{
		if(!parse_matchlist(m_filesystem_details->m_readwrite_paths,
				    val["readWritePaths"]))
		{
			return false;
		}
	}

	if(val.isMember("readPaths"))
	{
		if(!parse_matchlist(m_filesystem_details->m_readonly_paths,
				    val["readPaths"]))
		{
			return false;
		}
	}

	return true;
}

bool security_rule_library::rule::parse_syscall_details(const Json::Value &val)
{
	if(!val.isMember("syscalls"))
	{
		return false;
	}

	m_syscall_details = std::unique_ptr<syscall_details>(new syscall_details());

	return parse_matchlist(m_syscall_details->m_syscalls,
			      val["syscalls"]);
}

bool security_rule_library::rule::parse_container_details(const Json::Value &val)
{
	if(!val.isMember("containers"))
	{
		return false;
	}

	m_container_details = std::unique_ptr<container_details>(new container_details());

	return parse_matchlist(m_container_details->m_containers,
			      val["containers"]);

	return true;
}

bool security_rule_library::rule::parse_network_details(const Json::Value &val)
{
	if((!val.isMember("tcpListenPorts") &&
	    !val.isMember("udpListenPorts")) ||
	   !val.isMember("allOutbound") ||
	   !val["allOutbound"].isConvertibleTo(Json::booleanValue) ||
	   !val.isMember("allInbound") ||
	   !val["allInbound"].isConvertibleTo(Json::booleanValue))
	{
		fprintf(stderr, "FAIL4\n");
		return false;
	}

	m_network_details = std::unique_ptr<network_details>(new network_details());

	if(val.isMember("tcpListenPorts"))
	{
		if(!parse_matchlist(m_network_details->m_tcp_listen_ports,
				    val["tcpListenPorts"]))
		{
			return false;
		}
	}

	if(val.isMember("udpListenPorts"))
	{
		if(!parse_matchlist(m_network_details->m_udp_listen_ports,
				    val["udpListenPorts"]))
		{
			return false;
		}
	}

	m_network_details->m_all_outbound = val["allOutbound"].asBool();
	m_network_details->m_all_inbound = val["allInbound"].asBool();

	return true;
}

bool security_rule_library::parse(const Json::Value &val, rule_sptr &rule)
{
	g_log->debug("parsing Fastengine Rule " + Json::FastWriter().write(val));

	if(!val.isObject() ||
	   !val.isMember("name") ||
	   !val["name"].isConvertibleTo(Json::stringValue) ||
	   !val.isMember("details") ||
	   !val["details"].isObject() ||
	   !val["details"].isMember("ruleType") ||
	   !val["details"]["ruleType"].isConvertibleTo(Json::stringValue))
	{
		return false;
	}

	draiosproto::policy_type rule_type;
	std::string rule_type_str = val["details"]["ruleType"].asString();

	if(rule_type_str == "PROCESS")
	{
		rule_type = draiosproto::PTYPE_PROCESS;
	}
	else if(rule_type_str == "FILESYSTEM")
	{
		rule_type = draiosproto::PTYPE_FILESYSTEM;
	}
	else if(rule_type_str == "SYSCALL")
	{
		rule_type = draiosproto::PTYPE_SYSCALL;
	}
	else if(rule_type_str == "CONTAINER")
	{
		rule_type = draiosproto::PTYPE_CONTAINER;
	}
	else if(rule_type_str == "NETWORK")
	{
		rule_type = draiosproto::PTYPE_NETWORK;
	}
	else if(rule_type_str == "FALCO")
	{
		// Falco rules should not included in the json array
		return false;
	}
	else
	{
		g_log->debug("security_rule: Unknown rule type " + rule_type_str);

		return false;
	}

	rule = std::make_shared<security_rule_library::rule>(val["name"].asString(), rule_type);

	switch(rule->rule_type())
	{
	case draiosproto::PTYPE_PROCESS:
		if(!rule->parse_process_details(val["details"]))
		{
			rule = NULL;
			return false;
		}
		break;
	case draiosproto::PTYPE_FILESYSTEM:
		if(!rule->parse_filesystem_details(val["details"]))
		{
			rule = NULL;
			return false;
		}
		break;
	case draiosproto::PTYPE_SYSCALL:
		if(!rule->parse_syscall_details(val["details"]))
		{
			rule = NULL;
			return false;
		}
		break;
	case draiosproto::PTYPE_CONTAINER:
		if(!rule->parse_container_details(val["details"]))
		{
			rule = NULL;
			return false;
		}
		break;
	case draiosproto::PTYPE_NETWORK:
		if(!rule->parse_network_details(val["details"]))
		{
			rule = NULL;
			return false;
		}
		break;

	case draiosproto::PTYPE_FALCO:
	default:
		rule = NULL;
		return false;
	}

	g_log->debug("Parsed fastengine rule: " + rule->as_string());

	return true;
}

security_rule_library::security_rule_library()
{
}

security_rule_library::~security_rule_library()
{
}

bool security_rule_library::parse(const std::string &rule_defs_str)
{
	Json::Value rule_defs;
	bool collect_comments = false;

	try {
		if(!m_json_reader.parse(rule_defs_str, rule_defs, collect_comments))
		{
			return false;
		}

		if(rule_defs.isNull() ||
		   !rule_defs.isArray())
		{
			return false;
		}

		for(uint32_t i=0; i<rule_defs.size(); i++)
		{
			rule_sptr rule;

			if(!parse(rule_defs[i], rule))
			{
				g_log->error("Could not parse rule " +
					     to_string(i) +
					     " from rules json array");
				return false;
			}

			if(m_rules.find(rule->name()) != m_rules.end())
			{
				g_log->error("Could not add rule " +
					     rule->name() +
					     " from rules json array--entry with name already exists");
				return false;
			}

			m_rules.insert(std::make_pair(rule->name(), rule));
		}
	}
	catch (Json::Exception &e)
	{
		g_log->error("Could not parse rules object: \"" + rule_defs_str + "\": " + e.what());
		return false;
	}

	return true;
}

void security_rule_library::reset()
{
	m_rules.clear();
}

rule_sptr security_rule_library::find(const std::string &name)
{
	auto it = m_rules.find(name);
	if(it == m_rules.end())
	{
		rule_sptr r;
		return r;
	}

	return it->second;
}

security_rules::security_rules()
	: m_num_loaded_rules(0)
{
	m_evttypes.assign(PPM_EVENT_MAX+1, false);
	m_evtsources.assign(ESRC_MAX+1, false);
}

security_rules::~security_rules()
{
}

void security_rules::init(dragent_configuration *configuration,
			  sinsp *inspector,
			  std::shared_ptr<security_rule_library> library,
			  std::shared_ptr<security_evt_metrics> metrics)
{
	m_configuration = configuration;
	m_inspector = inspector;
	m_metrics = metrics;
	m_fastengine_rules_library = library;

	m_formatters = make_unique<sinsp_evt_formatter_cache>(inspector);

	if(qualifies() != "")
	{
		sinsp_filter_compiler compiler(inspector, qualifies());
		m_qualifies.reset(compiler.compile());
	}
}

std::string &security_rules::name()
{
	return m_name;
}

uint64_t security_rules::num_loaded_rules()
{
	return m_num_loaded_rules;
}

void security_rules::set_match_details(draiosproto::event_detail &details, bool match_items, sinsp_evt *evt)
{
	if(match_items)
	{
		m_metrics->incr(security_evt_metrics::EVM_MATCH_ITEMS);
	}
	else
	{
		m_metrics->incr(security_evt_metrics::EVM_NOT_MATCH_ITEMS);
	}

	details.mutable_output_details()->set_output_type(rules_type());
	if(rules_subtype() != draiosproto::PSTYPE_NOSUBTYPE)
	{
		details.mutable_output_details()->set_output_subtype(rules_subtype());
	}

	details.set_on_default(false);

	std::set<std::string> ofks = { "proc.name", "proc.cmdline" };
	std::set<std::string> default_ofks = default_output_fields_keys(evt);
	ofks.insert(default_ofks.begin(), default_ofks.end());

	for(const auto &ofk: ofks)
	{
		if(ofk != "falco.rule")
		{
			string format{"%" + ofk};
			string res;
			m_formatters->tostring(evt, format, &res);
			(*details.mutable_output_details()->mutable_output_fields())[ofk] = res;
		}
	}
}

void security_rules::set_match_details(draiosproto::event_detail &details, bool match_items, json_event *evt)
{
	if(match_items)
	{
		m_metrics->incr(security_evt_metrics::EVM_MATCH_ITEMS);
	}
	else
	{
		m_metrics->incr(security_evt_metrics::EVM_NOT_MATCH_ITEMS);
	}

	details.mutable_output_details()->set_output_type(rules_type());
	if(rules_subtype() != draiosproto::PSTYPE_NOSUBTYPE)
	{
		details.mutable_output_details()->set_output_subtype(rules_subtype());
	}

	details.set_on_default(false);
}

std::string security_rules::qualifies()
{
	return string("");
}

bool security_rules::event_qualifies(sinsp_evt *evt)
{
	if(m_qualifies && !m_qualifies->run(evt))
	{
		m_metrics->incr(security_evt_metrics::EVM_MISS_QUAL);
		return false;
	}

	return true;
}

falco_security_rules::falco_security_rules()
{
	m_name = "falco";
	m_evtsources[ESRC_SINSP] = true;
	m_evtsources[ESRC_K8S_AUDIT] = true;
	// All k8s audit events have the single tag "1". - see falco_engine::process_k8s_audit_event
	m_evttypes[1] = true;
}

falco_security_rules::~falco_security_rules()
{
}

void falco_security_rules::init(dragent_configuration *configuration,
				sinsp *inspector,
				std::shared_ptr<security_rule_library> library,
				std::shared_ptr<security_evt_metrics> metrics)
{
	security_rules::init(configuration, inspector, library, metrics);
}

void falco_security_rules::set_engine(std::shared_ptr<falco_engine> falco_engine)
{
	m_falco_engine = falco_engine;
}

void falco_security_rules::add_policy(policy_v2_sptr policy)
{
	if(m_falco_engine && policy->enabled())
	{
		// Use the name to create a ruleset. We'll use this
		// ruleset to run only the subset of rules we're
		// interested in.
		string all_rules = ".*";
		string ruleset = policy->name();

		// TODO: if this ruleset is already present, don't do again this initialization

		// We *only* want those rules selected by name/tags, so first disable all rules.
		m_falco_engine->enable_rule(all_rules, false, ruleset);

		// Now enable all rules named in the policy. Not all
		// of these are necessarily falco rules, they could
		// also be fast engine rules. That should be okay though.
		for(auto &rule_name : policy->rule_names())
		{
			m_falco_engine->enable_rule(rule_name, true, ruleset);
		}

		if(m_falco_engine->num_rules_for_ruleset(ruleset) > 0)
		{
			g_log->debug("Number of falco rules for policy " + policy->name() + " : " + std::to_string(m_falco_engine->num_rules_for_ruleset(ruleset)));
		}

		m_num_loaded_rules += m_falco_engine->num_rules_for_ruleset(ruleset);

		m_rulesets.insert(std::make_pair(m_falco_engine->find_ruleset_id(ruleset), policy));

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
	}
}

void falco_security_rules::reset()
{
	m_evttypes.clear();
	m_evtsources.clear();
	m_rulesets.clear();

	m_num_loaded_rules = 0;
}

draiosproto::policy_type falco_security_rules::rules_type()
{
	return draiosproto::PTYPE_FALCO;
}

draiosproto::policy_subtype falco_security_rules::rules_subtype()
{
	return draiosproto::PSTYPE_NOSUBTYPE;
}

std::set<std::string> falco_security_rules::default_output_fields_keys(sinsp_evt *evt)
{
	// falco policies handle this internally
	return {};
}

bool falco_security_rules::check_conditions(sinsp_evt *evt)
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

bool falco_security_rules::check_conditions(json_event *evt)
{
	if(!m_falco_engine)
	{
		m_metrics->incr(security_evt_metrics::EVM_MISS_NO_FALCO_ENGINE);
		return false;
	}

	return true;
}

std::list<security_rules::match_result> falco_security_rules::match_event(sinsp_evt *evt)
{
	std::list<match_result> results;

	if(!check_conditions(evt))
	{
		return results;
	}

	for(auto &ruleset : m_rulesets)
	{
		try {
			unique_ptr<falco_engine::rule_result> res = m_falco_engine->process_sinsp_event(evt, ruleset.first);

			if(!res)
			{
				m_metrics->incr(security_evt_metrics::EVM_MISS_CONDS);
			}
			else
			{
				g_log->debug("Event matched falco rules: rule=" + res->rule);

				// We don't need to worry about which rule matched in a given ruleset--falco handles that internally.
				match_result result;

				result.m_rule_name = res->rule;
				result.m_rule_type = draiosproto::PTYPE_FALCO;
				result.m_policy = ruleset.second;

				string output;
				m_formatters->tostring(evt, res->format, &output);
				result.m_detail.mutable_output_details()->set_output(output);
				(*result.m_detail.mutable_output_details()->mutable_output_fields())["falco.rule"] = res->rule;
				map<string,string> rule_output_fields;
				m_formatters->resolve_tokens(evt, res->format, rule_output_fields);
				for(const auto &rof : rule_output_fields)
				{
					(*result.m_detail.mutable_output_details()->mutable_output_fields())[rof.first] = rof.second;
				}
				bool match_items = true;
				set_match_details(result.m_detail, match_items, evt);
				results.push_back(result);
			}
		}
		catch (falco_exception& e)
		{
			g_log->error("Error processing sinsp event against falco engine: " + string(e.what()));
		}
	}

	return results;
}

std::list<security_rules::match_result> falco_security_rules::match_event(json_event *evt)
{
	std::list<match_result> results;

	if(!check_conditions(evt))
	{
		return results;
	}

	for(auto &ruleset : m_rulesets)
	{
		try {
			unique_ptr<falco_engine::rule_result> res = m_falco_engine->process_k8s_audit_event(evt, ruleset.first);

			if(!res)
			{
				m_metrics->incr(security_evt_metrics::EVM_MISS_CONDS);
			}
			else
			{
				g_log->debug("Event matched falco rules: rule=" + res->rule);

				// XXX/mstemm the match_infos could really be created once.
				match_result result;

				result.m_rule_name = res->rule;
				result.m_rule_type = draiosproto::PTYPE_FALCO;
				result.m_policy = ruleset.second;

				json_event_formatter jevt_formatter(m_falco_engine->json_factory(), res->format);
				result.m_detail.mutable_output_details()->set_output(jevt_formatter.tostring(evt));
				(*result.m_detail.mutable_output_details()->mutable_output_fields())["falco.rule"] = res->rule;

				std::list<std::pair<std::string,std::string>> resolved_tokens;
				jevt_formatter.resolve_tokens(evt, resolved_tokens);
				for (const auto &rt : resolved_tokens)
				{
 					if (!rt.first.empty() && !rt.second.empty())
					{
						(*result.m_detail.mutable_output_details()->mutable_output_fields())[rt.first] = rt.second;
					}
				}

				bool match_items = true;
				set_match_details(result.m_detail, match_items, evt);
				results.push_back(result);
			}
		}
		catch (falco_exception& e)
		{
			g_log->error("Error processing k8s audit event against falco engine: " + string(e.what()));
		}
	}

	return results;
}

void matchlist_security_rules::match_info_set::add(const matchlist_security_rules::match_info &minfo)
{
	m_cur_matches.insert(std::make_pair(minfo.m_rule->name(), minfo.m_policy->id()));
}

bool matchlist_security_rules::match_info_set::contains(const matchlist_security_rules::match_info &minfo)
{
	return (m_cur_matches.find(std::make_pair(minfo.m_rule->name(), minfo.m_policy->id())) != m_cur_matches.end());
}

matchlist_security_rules::matchlist_security_rules()
{
	m_evtsources[ESRC_SINSP] = true;
}

matchlist_security_rules::~matchlist_security_rules()
{

}

namespace std {
	template <> struct hash<matchlist_security_rules::match_info>
	{
		std::size_t operator()(const matchlist_security_rules::match_info& info) const
		{
			return ((hash<security_policy_v2 *>()(info.m_policy.get()))
				^ (hash<security_rule_library::rule *>()(info.m_rule.get()))
				^ (hash<bool>()(info.m_match_items)));
		}
	};
}

bool operator==(const matchlist_security_rules::match_info& a, const matchlist_security_rules::match_info& b)
{
	return (a.m_policy.get() == b.m_policy.get() &&
		a.m_rule.get() == b.m_rule.get() &&
		a.m_match_items == b.m_match_items);
}

void matchlist_security_rules::init(dragent_configuration *configuration,
				    sinsp *inspector,
				    std::shared_ptr<security_rule_library> library,
				    std::shared_ptr<security_evt_metrics> metrics)
{
	security_rules::init(configuration, inspector, library, metrics);
}

void matchlist_security_rules::add_policy(policy_v2_sptr policy)
{
	for(auto &rule_name : policy->rule_names())
	{
		rule_sptr rule = m_fastengine_rules_library->find(rule_name);

		if(rule && rule->rule_type() == rules_type())
		{
			g_log->debug("matchlist_security_rules: loading rules from policy " + to_string(policy->id()));

			if(add_rule(policy, rule))
			{
				m_num_loaded_rules++;
			}
		}
	}
}

void matchlist_security_rules::reset()
{
	m_num_loaded_rules = 0;
}

std::list<security_rules::match_result> matchlist_security_rules::match_event(json_event *evt)
{
	std::list<match_result> res;

	return res;
}

void matchlist_security_rules::add_default_match_rule(policy_v2_sptr policy, rule_sptr rule)
{
	match_info minfo;

	minfo.m_policy = policy;
	minfo.m_rule = rule;
	minfo.m_match_items = true;

	m_default_matches.push_back(minfo);
}

void matchlist_security_rules::add_default_matches(std::list<security_rules::match_result> &results,
						   match_info_set &cur_matches,
						   sinsp_evt *evt)
{
	for(auto &minfo : m_default_matches)
	{
		if(!cur_matches.contains(minfo))
		{
			match_result result;
			result.m_rule_name = minfo.m_rule->name();
			result.m_rule_type = minfo.m_rule->rule_type();
			result.m_policy = minfo.m_policy;
			bool match_items = false;
			set_match_details(result.m_detail, match_items, evt);

			results.push_back(result);
		}
	}
}

filtercheck_rules::filtercheck_rules()
{
}

filtercheck_rules::~filtercheck_rules()
{

}

void filtercheck_rules::init(dragent_configuration *configuration,
			     sinsp *inspector,
			     std::shared_ptr<security_rule_library> library,
			     std::shared_ptr<security_evt_metrics> metrics)
{
	matchlist_security_rules::init(configuration, inspector, library, metrics);
}

void filtercheck_rules::reset()
{
	matchlist_security_rules::reset();

	m_index.clear();
	m_val_storages.clear();
}

filter_value_t filtercheck_rules::add_filter_value(uint8_t *val, uint32_t len)
{
	m_val_storages.push_back(vector<uint8_t>(len));
	memcpy(&m_val_storages[m_val_storages.size()-1][0], val, len);

	return filter_value_t(&m_val_storages[m_val_storages.size()-1][0], len);
}

std::list<security_rules::match_result> filtercheck_rules::match_event(sinsp_evt *evt)
{
	std::list<match_result> results;
	match_info_set matches_found;

	if(!event_qualifies(evt))
	{
		return results;
	}

	uint8_t *val;
	uint32_t len;
	val = m_check->extract(evt, &len);

	if(!val)
	{
		m_metrics->incr(security_evt_metrics::EVM_MISS_CONDS);
		return results;
	}

	filter_value_t key(val, len);

	auto matches = m_index.equal_range(key);

	if(matches.first != matches.second)
	{
		for(auto it = matches.first; it != matches.second; ++it)
		{
			matches_found.add(it->second);

			if(it->second.m_match_items)
			{
				match_result result;
				result.m_rule_name = it->second.m_rule->name();
				result.m_rule_type = it->second.m_rule->rule_type();
				result.m_policy = it->second.m_policy;

				bool match_items = true;
				set_match_details(result.m_detail, match_items, evt);

				results.push_back(result);
			}
		}
	}

	// Also add any default matches for rules where we didn't find any values above.
	add_default_matches(results, matches_found, evt);

	return results;
}

net_inbound_rules::net_inbound_rules()
{
	m_name = "network-inbound";

	m_evttypes[PPME_SOCKET_ACCEPT_X] = true;
	m_evttypes[PPME_SOCKET_ACCEPT4_X] = true;
	m_evttypes[PPME_SOCKET_ACCEPT_5_X] = true;
	m_evttypes[PPME_SOCKET_ACCEPT4_5_X] = true;
	m_evttypes[PPME_SOCKET_RECVFROM_X] = true;
	m_evttypes[PPME_SOCKET_RECVMSG_X] = true;
}

net_inbound_rules::~net_inbound_rules()
{
}

void net_inbound_rules::init(dragent_configuration *configuration,
			     sinsp *inspector,
			     std::shared_ptr<security_rule_library> library,
			     std::shared_ptr<security_evt_metrics> metrics)
{
	matchlist_security_rules::init(configuration, inspector, library, metrics);
}

void net_inbound_rules::reset()
{
	matchlist_security_rules::reset();
	m_index.clear();
}

draiosproto::policy_type net_inbound_rules::rules_type()
{
	return draiosproto::PTYPE_NETWORK;
}

draiosproto::policy_subtype net_inbound_rules::rules_subtype()
{
	return draiosproto::PSTYPE_NETWORK_INBOUND;
}

std::set<std::string> net_inbound_rules::default_output_fields_keys(sinsp_evt *evt)
{
	return { "fd.l4proto", "fd.cip", "fd.cport", "fd.sip", "fd.sport" };
}

std::string net_inbound_rules::qualifies()
{
	// In plain words, this is:
	//   1. tcp accepts or udp receives where a source is specified and
	//   2. the fd represents an ipv4 or ipv6 connection and
	//   3. Both endpoints are not localhost or unspecified 0.0.0.0 addresses and
	//   4. The accept succeeded or was non-blocking and didn't immediately have an error.
	return string("((evt.type = accept and evt.dir=<) or "
		      " (evt.type in (recvfrom,recvmsg) and evt.dir=< and "
		      "  fd.l4proto != tcp and fd.connected=false and fd.name_changed=true)) and "
		      "(fd.typechar = 4 or fd.typechar = 6) and "
		      "(fd.ip != 0.0.0.0 and fd.net != 127.0.0.0/8) and "
		      "(evt.rawres >= 0 or evt.res = EINPROGRESS)"
		);
}

bool net_inbound_rules::add_rule(policy_v2_sptr policy,
				 rule_sptr rule)
{
	g_log->debug("net_inbound_rules: loading rule " + rule->name() + " from policy " + to_string(policy->id()));
	const security_rule_library::rule::network_details *details = rule->get_network_details();

	if(!details)
	{
		return false;
	}

	if((rules_subtype() == draiosproto::PSTYPE_NETWORK_INBOUND && details->m_all_inbound) ||
	   (rules_subtype() == draiosproto::PSTYPE_NETWORK_OUTBOUND && details->m_all_outbound))
	{
		add_default_match_rule(policy, rule);
		return true;
	}

	return false;
}

std::list<security_rules::match_result> net_inbound_rules::match_event(sinsp_evt *evt)
{
	std::list<match_result> results;
	match_info_set empty;

	if(!event_qualifies(evt))
	{
		return results;
	}

	// If here, the event matches all rules. Return them as match results.
	add_default_matches(results, empty, evt);

	return results;
}

net_outbound_rules::net_outbound_rules()
{
	m_name = "network-outbound";

	m_evttypes.assign(PPM_EVENT_MAX+1, false);
	m_evttypes[PPME_SOCKET_CONNECT_X] = true;
	m_evttypes[PPME_SOCKET_SENDTO_X] = true;
	m_evttypes[PPME_SOCKET_SENDMSG_X] = true;
}

net_outbound_rules::~net_outbound_rules()
{
}

draiosproto::policy_type net_outbound_rules::rules_type()
{
	return draiosproto::PTYPE_NETWORK;
}

draiosproto::policy_subtype net_outbound_rules::rules_subtype()
{
	return draiosproto::PSTYPE_NETWORK_OUTBOUND;
}

std::string net_outbound_rules::qualifies()
{
	return string("((evt.type = connect and evt.dir=<) or "
		      " (evt.type in (sendto,sendmsg) and evt.dir=< and "
		      "  fd.l4proto != tcp and fd.connected=false and fd.name_changed=true)) and "
		      "(fd.typechar = 4 or fd.typechar = 6) and "
		      "(fd.ip != 0.0.0.0 and fd.net != 127.0.0.0/8) and "
		      "(evt.rawres >= 0 or evt.res = EINPROGRESS)"
		);
}

tcp_listenport_rules::tcp_listenport_rules()
{
	m_name = "listenports-tcp";

	m_evttypes[PPME_SOCKET_LISTEN_E] = true;
}

tcp_listenport_rules::~tcp_listenport_rules()
{
}

void tcp_listenport_rules::init(dragent_configuration *configuration,
				   sinsp *inspector,
				   std::shared_ptr<security_rule_library> library,
				   std::shared_ptr<security_evt_metrics> metrics)
{
	filtercheck_rules::init(configuration, inspector, library, metrics);

	m_check.reset(g_filterlist.new_filter_check_from_fldname("fd.sport", m_inspector, true));
	m_check->parse_field_name("fd.sport", true, false);
}

draiosproto::policy_type tcp_listenport_rules::rules_type()
{
	return draiosproto::PTYPE_NETWORK;
}

draiosproto::policy_subtype tcp_listenport_rules::rules_subtype()
{
	return draiosproto::PSTYPE_NETWORK_LISTENING;
}

std::set<std::string> tcp_listenport_rules::default_output_fields_keys(sinsp_evt *evt)
{
	return { "fd.l4proto", "fd.sip", "fd.sport" };
}

std::string tcp_listenport_rules::qualifies()
{
	return string("fd.l4proto = tcp");
}

void tcp_listenport_rules::add_ports(const security_rule_library::rule::match_list &mlist,
				     policy_v2_sptr policy,
				     rule_sptr rule)
{
	for(auto &portstr : mlist.m_items)
	{
		uint16_t port = (uint16_t) strtoul(portstr.c_str(), NULL, 10);
		filter_value_t key = add_filter_value((uint8_t *) &port, sizeof(uint16_t));

		match_info minfo;
		minfo.m_policy = policy;
		minfo.m_rule = rule;
		minfo.m_match_items = mlist.m_match_items;

		m_index.insert(std::make_pair(key, minfo));
	}

	if(!mlist.m_match_items)
	{
		// Also add a default match so ports outside
		// the list result in a rule match.
		add_default_match_rule(policy, rule);
	}
}
bool tcp_listenport_rules::add_rule(policy_v2_sptr policy,
				    rule_sptr rule)
{
	g_log->debug("tcp_listenport_rules: loading rule " + rule->name() + " from policy " + to_string(policy->id()));

	const security_rule_library::rule::network_details *details = rule->get_network_details();

	if(!details)
	{
		return false;
	}

	if(details->m_tcp_listen_ports.m_items.size() > 0)
	{
		add_ports(details->m_tcp_listen_ports, policy, rule);
		return true;
	}

	return false;
}

udp_listenport_rules::udp_listenport_rules()
{
	m_name = "listenports-udp";

	m_evttypes.assign(PPM_EVENT_MAX+1, false);
	m_evttypes[PPME_SOCKET_RECVFROM_E] = true;
	m_evttypes[PPME_SOCKET_RECVMSG_E] = true;
}

udp_listenport_rules::~udp_listenport_rules()
{
}

std::string udp_listenport_rules::qualifies()
{
	return string("fd.l4proto = udp and fd.connected = false");
}

bool udp_listenport_rules::add_rule(policy_v2_sptr policy,
				    rule_sptr rule)
{
	g_log->debug("udp_listenport_rules: loading rule " + rule->name() + " from policy " + to_string(policy->id()));

	const security_rule_library::rule::network_details *details = rule->get_network_details();

	if(!details)
	{
		return false;
	}

	if(details->m_udp_listen_ports.m_items.size() > 0)
	{
		add_ports(details->m_udp_listen_ports, policy, rule);
		return true;
	}

	return false;
}

syscall_rules::syscall_rules()
{
	m_name = "syscalls";

	for(uint32_t j = 0; j < PPM_EVENT_MAX; j++)
	{
		// Skip container events, they aren't a result of executed programs.
		if(j == PPME_CONTAINER_JSON_E)
		{
			continue;
		}

		if(PPME_IS_ENTER(j))
		{
			m_evttypes[j] = true;
		}
	}
}

syscall_rules::~syscall_rules()
{
}

void syscall_rules::init(dragent_configuration *configuration,
			 sinsp *inspector,
			 std::shared_ptr<security_rule_library> library,
			 std::shared_ptr<security_evt_metrics> metrics)
{
	matchlist_security_rules::init(configuration, inspector, library, metrics);

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

void syscall_rules::reset()
{
	matchlist_security_rules::reset();

	m_event_index.clear();
	m_event_index.resize(PPM_EVENT_MAX+1);

	m_syscall_index.clear();
	m_syscall_index.resize(PPM_SC_MAX+1);
}

draiosproto::policy_type syscall_rules::rules_type()
{
	return draiosproto::PTYPE_SYSCALL;
}

draiosproto::policy_subtype syscall_rules::rules_subtype()
{
	return draiosproto::PSTYPE_NOSUBTYPE;
}

std::set<std::string> syscall_rules::default_output_fields_keys(sinsp_evt *evt)
{
	return { "evt.type" };
}

bool syscall_rules::event_qualifies(sinsp_evt *evt)
{
	return evt->falco_consider();
}

bool syscall_rules::add_rule(policy_v2_sptr policy,
			     rule_sptr rule)
{
	bool added = false;

	g_log->debug("syscall_rules: loading rule " + rule->name() + " from policy " + to_string(policy->id()));

	const security_rule_library::rule::syscall_details *details = rule->get_syscall_details();

	if(!details)
	{
		return added;
	}

	for(auto &evtstr : details->m_syscalls.m_items)
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

				added = true;
				match_info minfo;
				minfo.m_policy = policy;
				minfo.m_rule = rule;
				minfo.m_match_items = details->m_syscalls.m_match_items;

				m_event_index[evtnum].push_back(minfo);
			}
		}

		auto it2 = m_syscallnums.find(evtstr);

		if(it2 != m_syscallnums.end())
		{
			if(sinsp::falco_consider_syscallid(it2->second))
			{

				added = true;

				match_info minfo;
				minfo.m_policy = policy;
				minfo.m_rule = rule;
				minfo.m_match_items = details->m_syscalls.m_match_items;

				m_syscall_index[it2->second].push_back(minfo);
			}

		}
	}

	if(!details->m_syscalls.m_match_items)
	{
		added = true;
		add_default_match_rule(policy, rule);
	}

	return added;
}

std::list<security_rules::match_result> syscall_rules::match_event(sinsp_evt *evt)
{
	std::list<match_result> results;
	match_info_set matches_found;

	uint16_t etype = evt->get_type();

	if(!event_qualifies(evt))
	{
		return results;
	}

	if(etype == PPME_GENERIC_E || etype == PPME_GENERIC_X)
	{
		sinsp_evt_param *parinfo = evt->get_param(0);
		ASSERT(parinfo->m_len == sizeof(uint16_t));
		uint16_t evid = *(uint16_t *)parinfo->m_val;

		for(auto &minfo : m_syscall_index[evid])
		{
			matches_found.add(minfo);

			if(minfo.m_match_items)
			{
				match_result result;
				result.m_rule_name = minfo.m_rule->name();
				result.m_rule_type = minfo.m_rule->rule_type();
				result.m_policy = minfo.m_policy;

				bool match_items = true;
				set_match_details(result.m_detail, match_items, evt);

				results.push_back(result);
			}
		}
	}
	else
	{
		for(auto &minfo : m_event_index[etype])
		{
			matches_found.add(minfo);

			if(minfo.m_match_items)
			{
				match_result result;
				result.m_rule_name = minfo.m_rule->name();
				result.m_rule_type = minfo.m_rule->rule_type();
				result.m_policy = minfo.m_policy;

				bool match_items = true;
				set_match_details(result.m_detail, match_items, evt);

				results.push_back(result);
			}
		}
	}

	// Also add default matches for any rules not found above
	add_default_matches(results, matches_found, evt);

	return results;
}

matchlist_map_security_rules::matchlist_map_security_rules()
{
}

matchlist_map_security_rules::~matchlist_map_security_rules()
{
}

void matchlist_map_security_rules::init(dragent_configuration *configuration,
					sinsp *inspector,
					std::shared_ptr<security_rule_library> library,
					std::shared_ptr<security_evt_metrics> metrics)
{
	matchlist_security_rules::init(configuration, inspector, library, metrics);

	m_index.reset(new path_prefix_map<std::unordered_set<match_info>>());
}

void matchlist_map_security_rules::reset()
{
	matchlist_security_rules::reset();

	m_vals.clear();
	m_index.reset(new path_prefix_map<std::unordered_set<match_info>>());
}

std::list<security_rules::match_result> matchlist_map_security_rules::match_event(sinsp_evt *evt)
{
	std::list<match_result> results;
	match_info_set matches_found;

	if(!event_qualifies(evt))
	{
		return results;
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
			return results;
		}

		filter_value_t key(val, len);
		filter_components_t components;

		split_components(key, components);

		const std::unordered_set<match_info> *found = m_index->match_components(components);

		if((found = m_index->match_components(components)) != NULL)
		{
			for(auto &minfo : *found)
			{
				// Don't let a single rule + policy have
				// multiple matches for a single
				// event. This can occur for RENAMEAT,
				// where it looks both at the source
				// and destination arguments of the
				// syscall.
				if(!matches_found.contains(minfo))
				{
					matches_found.add(minfo);

					if(minfo.m_match_items)
					{
						match_result result;
						result.m_rule_name = minfo.m_rule->name();
						result.m_rule_type = minfo.m_rule->rule_type();
						result.m_policy = minfo.m_policy;

						bool match_items = true;
						set_match_details(result.m_detail, match_items, evt);

						results.push_back(result);
					}
				}
			}
		}
	}

	add_default_matches(results, matches_found, evt);

	return results;
}

bool matchlist_map_security_rules::add_rule(policy_v2_sptr policy,
					    rule_sptr rule)
{
	bool added = false;

	g_log->debug("matchlist_map_security_rules (" + to_string(rules_type()) + "): loading rule " + rule->as_string() + " from policy " + to_string(policy->id()));

	const security_rule_library::rule::match_list *list = get_match_list(rule);

	if(!list || list->m_items.size() == 0)
	{
		return added;
	}

	for(auto &val : list->m_items)
	{
		m_vals.push_back(val);
		filter_value_t key = make_pair((uint8_t *) m_vals.back().c_str(), m_vals.back().length());

		filter_components_t components;
		split_components(key, components);

		std::unordered_set<match_info> *cur = m_index->match_components(components);

		if(cur == NULL)
		{
			std::unordered_set<match_info> new_set;

			// Don't need to allocate this, prefix_search_map
			// makes its own copy.
			m_index->add_search_path_components(components, new_set);

			cur = m_index->match_components(components);

			if(cur == NULL)
			{
				g_log->error("matchlist_map_security_rules::add_rule: Could not find list we just added?");
				return added;
			}
		}

		match_info minfo;
		minfo.m_policy = policy;
		minfo.m_rule = rule;
		minfo.m_match_items = list->m_match_items;

		cur->insert(minfo);

		added = true;
	}

	if(!list->m_match_items)
	{
		add_default_match_rule(policy, rule);
		added = true;
	}

	return added;
}

readonly_fs_rules::readonly_fs_rules()
{
	m_name = "files-readonly";

	m_evttypes[PPME_SYSCALL_OPEN_X] = true;
	m_evttypes[PPME_SYSCALL_OPENAT_2_X] = true;
}

readonly_fs_rules::~readonly_fs_rules()
{
}

void readonly_fs_rules::init(dragent_configuration *configuration,
				sinsp *inspector,
				std::shared_ptr<security_rule_library> library,
				std::shared_ptr<security_evt_metrics> metrics)
{
	matchlist_map_security_rules::init(configuration, inspector, library, metrics);

	std::shared_ptr<sinsp_filter_check> fdn;
	fdn.reset(g_filterlist.new_filter_check_from_fldname("fd.name", m_inspector, true));
	fdn->parse_field_name("fd.name", true, false);
	m_checks.emplace(PPME_SYSCALL_OPEN_X, fdn);
	m_checks.emplace(PPME_SYSCALL_OPENAT_2_X, fdn);
}

draiosproto::policy_type readonly_fs_rules::rules_type()
{
	return draiosproto::PTYPE_FILESYSTEM;
}

draiosproto::policy_subtype readonly_fs_rules::rules_subtype()
{
	return draiosproto::PSTYPE_FILESYSTEM_READ;
}

std::set<std::string> readonly_fs_rules::default_output_fields_keys(sinsp_evt *evt)
{
	return { "evt.type", "fd.name" };
}

std::string readonly_fs_rules::qualifies()
{
	return string("evt.rawres > 0 and evt.is_open_read=true and evt.is_open_write=false");
}

void readonly_fs_rules::split_components(const filter_value_t &val, filter_components_t &components)
{
	split_path(val, components);
	// Add an initial "root" to the set of components. That
	// ensures that a top-level path of '/' still results in a
	// non-empty components list. For all other paths, there will
	// be a dummy 'root' prefix at the top of every path.
	components.emplace_front((uint8_t *) "root", 4);
}

const security_rule_library::rule::match_list *readonly_fs_rules::get_match_list(rule_sptr rule)
{
	const security_rule_library::rule::filesystem_details *details = rule->get_filesystem_details();

	if(!details)
	{
		return NULL;
	}

	return &(details->m_readonly_paths);
}

readwrite_fs_rules::readwrite_fs_rules()
{
	m_name = "files-readwrite";
}

readwrite_fs_rules::~readwrite_fs_rules()
{
}

draiosproto::policy_subtype readwrite_fs_rules::rules_subtype()
{
	return draiosproto::PSTYPE_FILESYSTEM_READWRITE;
}

std::string readwrite_fs_rules::qualifies()
{
	return string("evt.rawres > 0 and evt.is_open_write=true");
}

const security_rule_library::rule::match_list *readwrite_fs_rules::get_match_list(rule_sptr rule)
{
	const security_rule_library::rule::filesystem_details *details = rule->get_filesystem_details();

	if(!details)
	{
		return NULL;
	}

	return &(details->m_readwrite_paths);
}

nofd_readwrite_fs_rules::nofd_readwrite_fs_rules()
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

nofd_readwrite_fs_rules::~nofd_readwrite_fs_rules()
{
}

void nofd_readwrite_fs_rules::init(dragent_configuration *configuration,
				      sinsp *inspector,
				      std::shared_ptr<security_rule_library> library,
				      std::shared_ptr<security_evt_metrics> metrics)
{
	matchlist_map_security_rules::init(configuration, inspector, library, metrics);

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

std::set<std::string> nofd_readwrite_fs_rules::default_output_fields_keys(sinsp_evt *evt)
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

std::string nofd_readwrite_fs_rules::qualifies()
{
	return string("evt.rawres = 0");
}

container_rules::container_rules()
{
	m_name = "containers";

	m_evttypes[PPME_CONTAINER_JSON_E] = true;
}

container_rules::~container_rules()
{
}

void container_rules::init(dragent_configuration *configuration,
			      sinsp *inspector,
			      std::shared_ptr<security_rule_library> library,
			      std::shared_ptr<security_evt_metrics> metrics)
{
	matchlist_security_rules::init(configuration, inspector, library, metrics);

	std::shared_ptr<sinsp_filter_check> cim;
	cim.reset(g_filterlist.new_filter_check_from_fldname("container.image", m_inspector, true));
	cim->parse_field_name("container.image", true, false);
	m_checks.emplace(PPME_CONTAINER_JSON_E, cim);
}

draiosproto::policy_type container_rules::rules_type()
{
	return draiosproto::PTYPE_CONTAINER;
}

draiosproto::policy_subtype container_rules::rules_subtype()
{
	return draiosproto::PSTYPE_NOSUBTYPE;
}

std::set<std::string> container_rules::default_output_fields_keys(sinsp_evt *evt)
{
	return { "container.id", "container.name", "container.image", "container.image.id" };
}

std::string container_rules::qualifies()
{
	return string("evt.type=container");
}

void container_rules::split_components(const filter_value_t &val, filter_components_t &components)
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

const security_rule_library::rule::match_list *container_rules::get_match_list(rule_sptr rule)
{
	const security_rule_library::rule::container_details *details = rule->get_container_details();

	if(!details)
	{
		return NULL;
	}

	return &(details->m_containers);
}

process_rules::process_rules()
{
	m_name = "processes";

	m_evttypes[PPME_SYSCALL_EXECVE_18_X] = true;
	m_evttypes[PPME_SYSCALL_EXECVE_19_X] = true;
}

process_rules::~process_rules()
{
}

void process_rules::init(dragent_configuration *configuration,
			    sinsp *inspector,
			    std::shared_ptr<security_rule_library> library,
			    std::shared_ptr<security_evt_metrics> metrics)
{
	filtercheck_rules::init(configuration, inspector, library, metrics);

	m_check.reset(g_filterlist.new_filter_check_from_fldname("proc.name", m_inspector, true));
	m_check->parse_field_name("proc.name", true, false);
}

draiosproto::policy_type process_rules::rules_type()
{
	return draiosproto::PTYPE_PROCESS;
}

draiosproto::policy_subtype process_rules::rules_subtype()
{
	return draiosproto::PSTYPE_NOSUBTYPE;
}

std::set<std::string> process_rules::default_output_fields_keys(sinsp_evt *evt)
{
	return { "proc.name" };
}

bool process_rules::add_rule(policy_v2_sptr policy,
			     rule_sptr rule)
{
	bool added = false;

	g_log->debug("process_rules: loading rule " + rule->name() + " from policy " + to_string(policy->id()));

	const security_rule_library::rule::process_details *details = rule->get_process_details();

	if(!details)
	{
		return added;
	}

	for(auto &pname : details->m_processes.m_items)
	{
		filter_value_t key = add_filter_value((uint8_t *) pname.c_str(), pname.length());

		added = true;

		match_info minfo;
		minfo.m_policy = policy;
		minfo.m_rule = rule;
		minfo.m_match_items = details->m_processes.m_match_items;

		m_index.insert(std::make_pair(key, minfo));
	}

	if(!details->m_processes.m_match_items)
	{
		added = true;
		add_default_match_rule(policy, rule);
	}

	return added;
}
#endif // CYGWING_AGENT
