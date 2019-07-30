#ifndef CYGWING_AGENT
#pragma once
#include <string>
#include <memory>
#include <vector>
#include <list>
#include <set>

#include "configuration.h"

#include <filter.h>
#include <filterchecks.h>
#include <filter_value.h>
#include <prefix_search.h>

#include <draios.pb.h>

#include <falco_engine.h>

typedef google::protobuf::RepeatedPtrField<draiosproto::scope_predicate> scope_predicates;

// Simple wrapper around draiosproto::policy_v2 that adds a few
// convienence methods.
class SINSP_PUBLIC security_policy_v2 : public draiosproto::policy_v2
{
public:
	security_policy_v2(const draiosproto::policy_v2 &policy_v2);
	virtual ~security_policy_v2();

	bool has_action(const draiosproto::action_type &atype);

	bool match_scope(std::string container_id, sinsp_analyzer *analyzer) const;
};

typedef std::shared_ptr<security_policy_v2> policy_v2_sptr;

class SINSP_PUBLIC security_rule_library
{
public:
	class rule {
	public:
		struct match_list
		{
			std::set<std::string> m_items;
			bool m_match_items;
		};

		struct process_details
		{
			match_list m_processes;
		};

		struct filesystem_details
		{
			match_list m_readwrite_paths;
			match_list m_readonly_paths;
		};

		struct syscall_details
		{
			match_list m_syscalls;
		};

		struct container_details
		{
			match_list m_containers;
		};

		struct network_details
		{
			bool m_all_outbound;
			bool m_all_inbound;

			match_list m_tcp_listen_ports;
			match_list m_udp_listen_ports;
		};

		rule(const std::string &name, draiosproto::policy_type rule_type);
		virtual ~rule();

		std::string &name();
		draiosproto::policy_type rule_type();

		std::string as_string();

		const process_details *get_process_details();
		const filesystem_details *get_filesystem_details();
		const syscall_details *get_syscall_details();
		const container_details *get_container_details();
		const network_details *get_network_details();

		bool parse_process_details(const Json::Value &val);
		bool parse_filesystem_details(const Json::Value &val);
		bool parse_syscall_details(const Json::Value &val);
		bool parse_container_details(const Json::Value &val);
		bool parse_network_details(const Json::Value &val);

	        bool parse_matchlist(struct match_list &list, const Json::Value &val);
	private:
		std::string m_name;
		draiosproto::policy_type m_rule_type;

		std::unique_ptr<process_details> m_process_details;
		std::unique_ptr<filesystem_details> m_filesystem_details;
		std::unique_ptr<syscall_details> m_syscall_details;
		std::unique_ptr<container_details> m_container_details;
		std::unique_ptr<network_details> m_network_details;
	};

	static bool parse(const Json::Value &val, std::shared_ptr<rule> &rule);

	security_rule_library();
	virtual ~security_rule_library();

	// Parse a string (json array) containing rule definitions
	bool parse(const std::string &rule_defs_str);

	// Clear all parsed information
	void reset();

	// Given a name, return a rule matching that name. The
	// returned shared_ptr.get() will be NULL if no matching rule
	// is found.
	std::shared_ptr<rule> find(const std::string &name);

private:

	Json::Reader m_json_reader;
	std::map<std::string,std::shared_ptr<rule>> m_rules;
};

typedef std::shared_ptr<security_rule_library::rule> rule_sptr;

//
// Perform parallel searches on a large (potentially >1k) number of
// rules. Each subclass has a specific way to hold and search
// through the set of rules and to to return all policies whose rules match
// the event.
//

// Overall class heirarchy:
// security_rules
//    - falco_security_rules
//    - matchlist_security_rules
//       - syscall_rules
//       - matchlist_map_security_rules
//          - readonly_fs_rules
//             - readwrite_fs_rules
//                - nofd_readwrite_fs_rules
//          - container_rules
//       - net_inbound_rules
//          - net_outbound_rules
//       - filtercheck_rules
//          - tcp_listenport_rules
//             - udp_listenport_rules
//          - process_rules

class SINSP_PUBLIC security_rules
{
public:

	class match_result
	{
	public:
		std::string m_rule_name;
		draiosproto::policy_type m_rule_type;
		policy_v2_sptr m_policy;
		draiosproto::event_detail m_detail;
		bool m_match_items;
	};

	security_rules();
	virtual ~security_rules();

	virtual void init(dragent_configuration *configuration,
			  sinsp *inspector,
			  std::shared_ptr<security_rule_library> library,
			  std::shared_ptr<security_evt_metrics> metrics);

	// Find all rules named in the provided policy that are applicable for this object and add them.
        virtual void add_policy(policy_v2_sptr policy) = 0;
	virtual void reset() = 0;

	// Return the rules type that this class implements.
	virtual draiosproto::policy_type rules_type() = 0;

	// Return the rules subtype that this class implements.
	virtual draiosproto::policy_subtype rules_subtype() = 0;

	virtual std::set<std::string> default_output_fields_keys(sinsp_evt *evt) = 0;

	// Given an event, match against the set of rules. Returns
	// match_result(s) matching the event, if any.
	std::list<match_result> match_event(gen_event *evt)
	{
		sinsp_evt * s_evt = NULL;
		json_event * j_evt = NULL;

		std::list<match_result> none;

		s_evt = dynamic_cast<sinsp_evt *>(evt);
		if (s_evt)
			return match_event(s_evt);

		j_evt = dynamic_cast<json_event *>(evt);
		if (j_evt)
			return match_event(j_evt);

		assert(false);
		return none;
	}
	virtual std::list<match_result> match_event(json_event *evt) = 0;
	virtual std::list<match_result> match_event(sinsp_evt *evt) = 0;

	// Return the number of rules loaded by this object.
	uint64_t num_loaded_rules();

	std::string &name();

	// Fill the requested information about the policy event
	void set_match_details(draiosproto::event_detail &details, bool match_items, sinsp_evt *evt);
	void set_match_details(draiosproto::event_detail &details, bool match_items, json_event *evt);

	// The event types and source for which this set of rules must run.
	std::vector<bool> m_evttypes;
	std::vector<bool> m_evtsources;

protected:

	// Expression to determine whether or not this event qualifies
	// for this set of rules, on top of any event type
	// filter. For example, for a file system rules the event
	// has to have evt.is_open_read=true.
	virtual std::string qualifies();

	// Match a sinsp_event against the expression in qualifies_exp().
	virtual bool event_qualifies(sinsp_evt *evt);

	std::string m_name;

	uint64_t m_num_loaded_rules;

	std::shared_ptr<security_evt_metrics> m_metrics;

	dragent_configuration *m_configuration;
	sinsp *m_inspector;
	std::shared_ptr<security_rule_library> m_fastengine_rules_library;

	unique_ptr<sinsp_evt_formatter_cache> m_formatters;

private:
	// This check is built from qualifies() and can be used to
	// match against a system event.
	std::unique_ptr<sinsp_filter> m_qualifies;
};

class SINSP_PUBLIC falco_security_rules : public security_rules
{
public:
	falco_security_rules();
	virtual ~falco_security_rules();

	void init(dragent_configuration *configuration,
		  sinsp *inspector,
		  std::shared_ptr<security_rule_library> library,
		  std::shared_ptr<security_evt_metrics> metrics) override;

        void add_policy(policy_v2_sptr policy) override;
	void reset() override;
	draiosproto::policy_type rules_type() override;
	draiosproto::policy_subtype rules_subtype() override;
	std::set<std::string> default_output_fields_keys(sinsp_evt *evt) override;

	std::list<match_result> match_event(json_event *evt) override;
	std::list<match_result> match_event(sinsp_evt *evt) override;

	void set_engine(std::shared_ptr<falco_engine> falco_engine);

private:

	bool check_conditions(sinsp_evt *evt);
	bool check_conditions(json_event *evt);

	std::shared_ptr<falco_engine> m_falco_engine;

	std::map<uint16_t, policy_v2_sptr> m_rulesets;
};

// Rules that work on matchlists are derived from this (abstract)
// class. Shares some common interfaces dealing with matchlists.
class SINSP_PUBLIC matchlist_security_rules : public security_rules
{
public:

	// If m_match_items is true, then when finding this info the
	// event should be considered matching the rule.
	class match_info {
	public:
		policy_v2_sptr m_policy;
		rule_sptr m_rule;
		bool m_match_items;
	};

	// Represent a collection of matches
	class match_info_set {
	public:
		void add(const match_info &minfo);
		bool contains(const match_info &minfo);

	private:
		std::set<std::pair<std::string,uint64_t>> m_cur_matches;
	};

	matchlist_security_rules();
	virtual ~matchlist_security_rules();

	virtual void init(dragent_configuration *configuration,
			  sinsp *inspector,
			  std::shared_ptr<security_rule_library> library,
			  std::shared_ptr<security_evt_metrics> metrics) override;

        void add_policy(policy_v2_sptr policy) override;

	virtual void reset() override;

	std::list<match_result> match_event(json_event *evt) override;
	virtual std::list<match_result> match_event(sinsp_evt *evt) = 0;

	virtual draiosproto::policy_type rules_type() = 0;
	virtual draiosproto::policy_subtype rules_subtype() = 0;
	virtual std::set<std::string> default_output_fields_keys(sinsp_evt *evt) = 0;

protected:

	// Add a policy + rule to the set of "default matching"
	// rules. This might either refer to rules that match all
	// qualifying events by default (e.g. network inbound/outbound
	// rules), or rules that do not match any of the items in the
	// associated matchlist (e.g. a list [a, b] + matchItems=false).
	void add_default_match_rule(policy_v2_sptr policy, rule_sptr rule);

	// Iterate over the set of default match rules, adding
	// match_results to the provided list. Any rules with names in
	// the provided set are skipped.
	void add_default_matches(std::list<match_result> &results,
				 match_info_set &cur_matches,
				 sinsp_evt *evt);

	// For matchlist rules, the subclass has to override something
	// slightly lower, loading any relevant information from the
	// provided rule. The caller will already have validated the
	// type to make sure it is relevant.
	//
	// Returns true if anything was loaded, false otherwise.
	virtual bool add_rule(policy_v2_sptr policy,
			      rule_sptr rule) = 0;

	std::list<match_info> m_default_matches;
};

class SINSP_PUBLIC syscall_rules : public matchlist_security_rules
{
public:
	syscall_rules();
	virtual ~syscall_rules();

	void init(dragent_configuration *configuration,
		  sinsp *inspector,
		  std::shared_ptr<security_rule_library> library,
		  std::shared_ptr<security_evt_metrics> metrics) override;

	void reset() override;
	draiosproto::policy_type rules_type() override;
	draiosproto::policy_subtype rules_subtype() override;
	std::set<std::string> default_output_fields_keys(sinsp_evt *evt) override;

	std::list<match_result> match_event(sinsp_evt *evt) override;

private:

	bool event_qualifies(sinsp_evt *evt) override;

	virtual bool add_rule(policy_v2_sptr policy,
			      rule_sptr rule) override;

	// Entry i in the vector is those rules that named event type i.
	std::vector<std::list<match_info>> m_event_index;

	// Maps from event name to list of ppm event numbers
	std::map<std::string,std::list<uint32_t>> m_evtnums;

	// Entry i in the vector is those rules that named syscall type i.
	std::vector<std::list<match_info>> m_syscall_index;

	// Maps from syscall name to syscall number
	std::map<std::string,uint32_t> m_syscallnums;

	const struct ppm_event_info *m_etable;
	const struct ppm_syscall_desc *m_stable;
};

//
// Each rule has sets of filterchecks and values that should
// match/should not match a given event.
//
// For a given sinsp event, the entire set of loaded rules are
// considered. Each filter check value is extracted and compared to
// the list of values for the match list. Events that either match the
// set of positive or negative values lead to a match result.
//

class SINSP_PUBLIC filtercheck_rules : public matchlist_security_rules
{
public:
	filtercheck_rules();
	virtual ~filtercheck_rules();

	virtual void init(dragent_configuration *configuration,
			  sinsp *inspector,
			  std::shared_ptr<security_rule_library> library,
			  std::shared_ptr<security_evt_metrics> metrics) override;

	void reset() override;
	virtual draiosproto::policy_type rules_type() = 0;
	virtual draiosproto::policy_subtype rules_subtype() = 0;
	virtual std::set<std::string> default_output_fields_keys(sinsp_evt *evt) = 0;

	std::list<match_result> match_event(sinsp_evt *evt) override;

protected:

	// Allocate storage for the filter value specified by val/len
	// and return a filter_value using that allocated storage.
        filter_value_t add_filter_value(uint8_t *val, uint32_t len);

	vector<vector<uint8_t>> m_val_storages;

	// The event attribute to extract. This is used to find the
	// set of possible rules that match the event. For example,
	// all file opens of a given file.
	std::unique_ptr<sinsp_filter_check> m_check;

	// Maps from filtercheck value to
	// match effect are filled in the result, but not the event
	// details.
	std::unordered_multimap<filter_value_t,
		match_info,
		g_hash_membuf,
		g_equal_to_membuf> m_index;
};

class SINSP_PUBLIC net_inbound_rules : public matchlist_security_rules
{
public:
	net_inbound_rules();
	virtual ~net_inbound_rules();

	void init(dragent_configuration *configuration,
		  sinsp *inspector,
		  std::shared_ptr<security_rule_library> library,
		  std::shared_ptr<security_evt_metrics> metrics) override;

	void reset() override;
	draiosproto::policy_type rules_type() override;
	draiosproto::policy_subtype rules_subtype() override;
	std::set<std::string> default_output_fields_keys(sinsp_evt *evt) override;

	std::list<match_result> match_event(sinsp_evt *evt) override;

protected:

	virtual bool add_rule(policy_v2_sptr policy,
			      rule_sptr rule) override;

	std::string qualifies() override;

	std::list<match_info> m_index;
};

class SINSP_PUBLIC net_outbound_rules : public net_inbound_rules
{
public:
	net_outbound_rules();
	virtual ~net_outbound_rules();

	draiosproto::policy_type rules_type() override;
	draiosproto::policy_subtype rules_subtype() override;

protected:
	std::string qualifies() override;
};

class SINSP_PUBLIC tcp_listenport_rules : public filtercheck_rules
{
public:
	tcp_listenport_rules();
	virtual ~tcp_listenport_rules();

	void init(dragent_configuration *configuration,
		  sinsp *inspector,
		  std::shared_ptr<security_rule_library> library,
		  std::shared_ptr<security_evt_metrics> metrics) override;

	draiosproto::policy_type rules_type() override;
	draiosproto::policy_subtype rules_subtype() override;
	std::set<std::string> default_output_fields_keys(sinsp_evt *evt) override;

protected:

	// Add ports from the provided list of strings to either the
	// index or default match list.
        void add_ports(const security_rule_library::rule::match_list &mlist,
		       policy_v2_sptr policy,
		       rule_sptr rule);

	virtual bool add_rule(policy_v2_sptr policy,
			      rule_sptr rule) override;

	std::string qualifies() override;
};

class SINSP_PUBLIC udp_listenport_rules : public tcp_listenport_rules
{
public:
	udp_listenport_rules();
	virtual ~udp_listenport_rules();

protected:

	virtual bool add_rule(policy_v2_sptr policy,
			      rule_sptr rule) override;

	std::string qualifies() override;
};

//
// Rules of this class use a prefix_map to compare events against matchlists
//
class SINSP_PUBLIC matchlist_map_security_rules : public matchlist_security_rules
{
public:
	matchlist_map_security_rules();
	virtual ~matchlist_map_security_rules();

	virtual void init(dragent_configuration *configuration,
			  sinsp *inspector,
			  std::shared_ptr<security_rule_library> library,
			  std::shared_ptr<security_evt_metrics> metrics) override;

	void reset() override;
	virtual draiosproto::policy_type rules_type() = 0;
	virtual draiosproto::policy_subtype rules_subtype() = 0;
	virtual std::set<std::string> default_output_fields_keys(sinsp_evt *evt) = 0;

	std::list<match_result> match_event(sinsp_evt *evt) override;


protected:

	virtual std::string qualifies() = 0;

	virtual bool add_rule(policy_v2_sptr policy,
			      rule_sptr rule) override;

	std::unordered_multimap<uint16_t, std::shared_ptr<sinsp_filter_check>> m_checks;

	std::list<std::string> m_vals;

	// Given a filter value, break it into components suitable for prefix matching
	virtual void split_components(const filter_value_t &val, path_prefix_map_ut::filter_components_t &components) = 0;

	// From the provided matchlist_detail message, return the
	// appropriate match_lists message.
	virtual const security_rule_library::rule::match_list *get_match_list(rule_sptr rule) = 0;

	std::unique_ptr<path_prefix_map<std::unordered_set<match_info>>> m_index;
};

class SINSP_PUBLIC readonly_fs_rules : public matchlist_map_security_rules
{
public:
	readonly_fs_rules();
	virtual ~readonly_fs_rules();

	void init(dragent_configuration *configuration,
		  sinsp *inspector,
		  std::shared_ptr<security_rule_library> library,
		  std::shared_ptr<security_evt_metrics> metrics) override;

	draiosproto::policy_type rules_type() override;
	draiosproto::policy_subtype rules_subtype() override;
	std::set<std::string> default_output_fields_keys(sinsp_evt *evt) override;

protected:

	std::string qualifies() override;

	void split_components(const filter_value_t &val, path_prefix_map_ut::filter_components_t &components);

	const security_rule_library::rule::match_list *get_match_list(rule_sptr rule) override;
};

class SINSP_PUBLIC readwrite_fs_rules : public readonly_fs_rules
{
public:
	readwrite_fs_rules();
	virtual ~readwrite_fs_rules();

	draiosproto::policy_subtype rules_subtype();

protected:

	const security_rule_library::rule::match_list *get_match_list(rule_sptr rule) override;

	std::string qualifies() override;
};

class SINSP_PUBLIC nofd_readwrite_fs_rules : public readwrite_fs_rules
{
public:
	nofd_readwrite_fs_rules();
	virtual ~nofd_readwrite_fs_rules();

	void init(dragent_configuration *configuration,
		  sinsp *inspector,
		  std::shared_ptr<security_rule_library> library,
		  std::shared_ptr<security_evt_metrics> metrics) override;

	std::set<std::string> default_output_fields_keys(sinsp_evt *evt) override;

protected:

	std::string qualifies() override;
};

class SINSP_PUBLIC container_rules : public matchlist_map_security_rules
{
public:
	container_rules();
	virtual ~container_rules();

	void init(dragent_configuration *configuration,
		  sinsp *inspector,
		  std::shared_ptr<security_rule_library> library,
		  std::shared_ptr<security_evt_metrics> metrics) override;

	draiosproto::policy_type rules_type() override;
	draiosproto::policy_subtype rules_subtype() override;
	std::set<std::string> default_output_fields_keys(sinsp_evt *evt) override;

protected:

	void split_components(const filter_value_t &val, path_prefix_map_ut::filter_components_t &components);

	const security_rule_library::rule::match_list *get_match_list(rule_sptr rule) override;

	std::string qualifies() override;
};

class SINSP_PUBLIC process_rules : public filtercheck_rules
{
public:
	process_rules();
	virtual ~process_rules();

	void init(dragent_configuration *configuration,
		  sinsp *inspector,
		  std::shared_ptr<security_rule_library> library,
		  std::shared_ptr<security_evt_metrics> metrics);

	draiosproto::policy_type rules_type() override;
	draiosproto::policy_subtype rules_subtype() override;
	std::set<std::string> default_output_fields_keys(sinsp_evt *evt) override;

private:

	virtual bool add_rule(policy_v2_sptr policy,
			      rule_sptr rule) override;
};
#endif // CYGWING_AGENT
