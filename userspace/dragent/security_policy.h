#ifndef CYGWING_AGENT
#pragma once
// A security policy represents a step in the security event
// workflow. It contains a scope and a set of actions to perform if
// the policy triggers.
//
// This class is virtual void and is the base class for falco_policy.

#include <string>
#include <memory>
#include <vector>
#include <algorithm>
#include <utility>

#include "configuration.h"

#include <filter.h>
#include <filterchecks.h>
#include <filter_value.h>
#include <prefix_search.h>

#include <draios.pb.h>

#include <falco_engine.h>

class security_mgr;

//
// Simple wrapper around draiosproto::policy that adds an order that
// reflects its position compared to other policies and a few
// convienence methods.
//

typedef google::protobuf::RepeatedPtrField<draiosproto::scope_predicate> scope_predicates;

class SINSP_PUBLIC security_policy : public draiosproto::policy
{
public:
	security_policy(const draiosproto::policy &policy);
	virtual ~security_policy();

	// Return the order in which this policy was received. Used to
	// prioritize one policy over another.
	inline uint64_t order() const
	{
		return m_order;
	}

	bool has_action(const draiosproto::action_type &atype);

	static bool match_scope(sinsp_evt *evt, sinsp_analyzer *analyzer,
				const ::scope_predicates &predicates,
				bool host_scope, bool container_scope);

protected:
	uint64_t m_order;
	static uint64_t m_next_order;
};

//
// Perform parallel searches on a large (potentially >1k) number of
// policies. Each subclass has a specific way to hold and search
// through the set of policies and to to return the policy with the
// lowest order, if any, that matches the event.
//

// Overall class heirarchy:
// security_policies
//    - falco_security_policies
//    - matchlist_security_policies
//       - syscall_policies
//       - matchlist_map_security_policies
//          - readonly_fs_policies
//             - readwrite_fs_policies
//          - container_policies
//       - filtercheck_policies
//          - net_inbound_policies
//             - net_outbound_policies
//          - tcp_listenport_policies
//             - udp_listenport_policies
//          - process_policies

class SINSP_PUBLIC security_policies
{
public:

	class match_result
	{
	public:
		// policy: the policy that matched the event
                // policies_type: the kind of policy (i.e. the policies object)
		//                that matched the event.
                // policies_subtype: the subkind of policy (i.e. r/rw for fs policies)
		//                that matched the event.
	        // item: the item within the policy that matched the
		//       event. The interpretation is up to the
		//       security_policies object. It's used as a
		//       general way to compare match results for the
		//       same policy. A match result with the same
		//       policy and a lower value for item will be
		//       preferred over a match result with a higher
		//       value for item.
		// detail: Details on the system event that matched.
		// effect: The effect to take based on the match.
		// ofk: The output field keys requested by the policy that
		//      matched the event.
		// baseline_id: If present, the id of the baseline that
		//              caused this match.

		match_result(security_policy *policy,
			     draiosproto::policy_type policies_type,
			     draiosproto::policy_subtype policies_subtype,
			     uint32_t item,
			     draiosproto::event_detail *detail,
			     draiosproto::match_effect effect,
			     const google::protobuf::RepeatedPtrField<std::string> &ofk,
			     const std::string &baseline_id = "");
		virtual ~match_result();

		static bool compare(const match_result &a, const match_result &b);
		static bool compare_ptr(const match_result *a, const match_result *b);

		security_policy *policy() const
		{
			return m_policy;
		}

		draiosproto::policy_type policies_type() const
		{
			return m_policies_type;
		}

		draiosproto::policy_subtype policies_subtype() const
		{
			return m_policies_subtype;
		}

		uint32_t item() const
		{
			return m_item;
		}

		draiosproto::event_detail *detail() const
		{
			return m_detail;
		}

		draiosproto::event_detail *take_detail()
		{
			draiosproto::event_detail *detail = m_detail;
			m_detail = NULL;

			return detail;
		}

		draiosproto::match_effect effect() const
		{
			return m_effect;
		}

		const google::protobuf::RepeatedPtrField<std::string>& output_field_keys() const
		{
			return m_ofk;
		}

		const std::string& baseline_id() const
		{
			return m_baseline_id;
		}

	private:
		security_policy *m_policy;
		draiosproto::policy_type m_policies_type;
		draiosproto::policy_subtype m_policies_subtype;
		uint32_t m_item;
		draiosproto::event_detail *m_detail;
		draiosproto::match_effect m_effect;
		google::protobuf::RepeatedPtrField<std::string> m_ofk;
		std::string m_baseline_id;
	};

	typedef std::list<match_result> match_result_list;

	// A scoped_match_result is just like a match_result but also
	// contains a scope_predicates value. It can be used internal
	// to subclasses to keep track of match_results that should
	// only be considered valid in a specific scope contetxt.
	class scoped_match_result : public match_result
        {
	public:
		scoped_match_result(const scope_predicates &predicates,
				    security_policy *policy,
				    draiosproto::policy_type policies_type,
				    draiosproto::policy_subtype policies_subtype,
				    uint32_t item,
				    draiosproto::event_detail *detail,
				    draiosproto::match_effect effect,
				    const google::protobuf::RepeatedPtrField<std::string> &ofk,
				    const std::string &baseline_id = "",
				    const scope_predicates &baseline_predicates = scope_predicates());

		virtual ~scoped_match_result();

		// Return whether or not this match result matches the
		// scope of the provided event.
                bool match_scope(sinsp_evt *evt, sinsp_analyzer *analyzer) const;

	private:

		scope_predicates m_predicates;
	};

	typedef std::list<scoped_match_result> scoped_match_result_list;

	security_policies();
	virtual ~security_policies();

	virtual void init(security_mgr *mgr,
			   dragent_configuration *configuration,
			   sinsp *inspector);

        virtual void add_policy(security_policy *policy) = 0;
	virtual void reset() = 0;

	// Return the policies type that this class implements.
	virtual draiosproto::policy_type policies_type() = 0;

	// Return the policies subtype that this class implements.
	virtual draiosproto::policy_subtype policies_subtype() = 0;

	// Given an event, match against the set of policies. Returns
	// the policy that matches the event, if any. If multiple
	// policies match the event, returns the one with the lowest
	// order.
	virtual match_result *match_event(sinsp_evt *evt) = 0;

	// Return the number of policies loaded by this object.
	virtual uint64_t num_loaded_policies() = 0;

	std::string &name();

	// Fill the requested information about the policy event
	void set_match_details(match_result &match, sinsp_evt *evt);

	// Log info on the number of events handled by this policy and what happened.
	void log_metrics();

	void reset_metrics();

	void add_to_internal_metrics(internal_metrics::sptr_t &metrics);

	// The event types for which this policy must run.
	std::vector<bool> m_evttypes;

protected:

	// Expression to determine whether or not this event qualifies
	// for this set of policies, on top of any event type
	// filter. For example, for a file system policies the event
	// has to have evt.is_open_read=true.
	virtual std::string qualifies();

	// Match a sinsp_event against the expression in qualifies_exp().
	bool event_qualifies(sinsp_evt *evt);

	std::string m_name;

	class evt_metrics : public internal_metrics::ext_source
	{
	public:
	        evt_metrics()
		{
		}

		virtual ~evt_metrics()
		{
		}

		void init(std::string &prefix, bool include_falco)
		{
			m_prefix = prefix;
			m_include_falco = include_falco;
		}

		enum reason
		{
			EVM_MATCH_ACCEPT = 0,
			EVM_MATCH_DENY,
			EVM_MATCH_NEXT,
			EVM_MISS_NO_FALCO_ENGINE,
			EVM_MISS_EF_DROP_FALCO,
			EVM_MISS_FALCO_EVTTYPE,
			EVM_MISS_SCOPE,
			EVM_MISS_QUAL,
			EVM_MISS_CONDS,
			EVM_MISS_DEFAULT_SCOPE,
			EVM_MAX
		};

		void incr(reason res)
		{
			m_metrics[res]++;
		}

		void reset()
		{
			std::fill_n(m_metrics, EVM_MAX, 0);
		}

		std::string to_string()
		{
			std::string str;

			for(uint32_t i = 0; i < EVM_MAX; i++)
			{
				str += " " + m_prefix + "." +
					m_metric_names[i] + "=" +
					std::to_string(m_metrics[i]);
			}

			return str;
		}

		virtual void send_all(draiosproto::statsd_info* statsd_info)
		{
			for(uint32_t i=0; i<EVM_MAX; i++)
			{
				if((i == EVM_MISS_NO_FALCO_ENGINE ||
				    i == EVM_MISS_EF_DROP_FALCO ||
				    i == EVM_MISS_FALCO_EVTTYPE) &&
				   !m_include_falco)
				{
					continue;
				}
				internal_metrics::write_metric(statsd_info,
							       std::string("security.") + m_prefix + "." + m_metric_names[i],
							       draiosproto::STATSD_COUNT,
							       m_metrics[i]);
				m_metrics[i] = 0;
			}
		}
	private:
		std::string m_prefix;
		bool m_include_falco;
		uint64_t m_metrics[EVM_MAX];
		std::string m_metric_names[EVM_MAX]{
			        "match.accept",
				"match.deny",
				"match.next",
				"miss.no_falco_engine",
				"miss.ef_drop_falco",
				"miss.falco_evttype",
				"miss.scope",
				"miss.qual",
				"miss.conds",
				"miss.default.scope"};

	};

	evt_metrics m_metrics;

	security_mgr *m_mgr;
	dragent_configuration *m_configuration;
	sinsp *m_inspector;

	unique_ptr<sinsp_evt_formatter_cache> m_formatters;

private:
	// This check is built from qualifies() and can be used to
	// match against a system event.
	std::unique_ptr<sinsp_filter> m_qualifies;
};

// Needed when using prefix_search match_result;
std::ostream &operator <<(std::ostream &os, const security_policies::match_result &res);

class SINSP_PUBLIC falco_security_policies : public security_policies
{
public:
	falco_security_policies();
	virtual ~falco_security_policies();

	void init(security_mgr *mgr,
		  dragent_configuration *configuration,
		  sinsp *inspector);

	void add_policy(security_policy *policy);
	void reset();
	draiosproto::policy_type policies_type();
	draiosproto::policy_subtype policies_subtype();

	bool load_rules(const draiosproto::policies &policies, std::string &errstr);

	match_result *match_event(sinsp_evt *evt);

	uint64_t num_loaded_policies();

private:

	bool check_conditions(sinsp_evt *evt);

	unique_ptr<falco_engine> m_falco_engine;

	std::map<security_policy *, uint16_t> m_rulesets;
};

// Policies that work on matchlists are derived from this (abstract)
// class. Shares some common interfaces dealing with matchlists.
class SINSP_PUBLIC matchlist_security_policies : public security_policies
{
public:
	matchlist_security_policies();
	virtual ~matchlist_security_policies();

	virtual void init(security_mgr *mgr,
			  dragent_configuration *configuration,
			  sinsp *inspector);

	void add_policy(security_policy *policy);

	virtual void reset();
	virtual draiosproto::policy_type policies_type() = 0;
	virtual draiosproto::policy_subtype policies_subtype() = 0;

	virtual match_result *match_event(sinsp_evt *evt) = 0;

	// Add a "default" match result that will be considered if an
	// event does *not* match the items specified by its matchlist
	// contents.
	//
	void add_default_match_result(scoped_match_result &res);

	// Return the best "default" match result from all those added
	// above. This also ensures that the scope of the event
	// matches the scope of the default. This memory is allocated
	// and must be freed by the caller (or passed to something
	// that will free it)
	match_result *min_default_match(sinsp_evt *evt, bool scope_miss);

	uint64_t num_loaded_policies();

protected:

	// For matchlist policies, the subclass has to override
	// something slightly lower, loading a policy and associated
	// matchlist_details object.
	//
	// predicates qualifies the entries in details so they only
	// match in the context of the provided scope predicates. (If
	// the entries in details should match regardless of scope,
	// provide a scope_predicates message with no entries).
	//
	// baseline_id contains the id of the baseline from which this
	// matchlist comes from. Empty otherwise.
	//
	// Returns true if anything was loaded, false otherwise.
	virtual bool add_matchlist_details(security_policy *policy,
					   const draiosproto::matchlist_detail &details,
					   const scope_predicates &predicates,
					   std::string baseline_id = "",
					   const scope_predicates &baseline_predicates = scope_predicates()) = 0;

	// While adding a smart policy, this method is used to check
	// if policy have requested to enforce baseline for this
	// policy type
	virtual inline bool is_baseline_requested(security_policy *policy) = 0;

	std::vector<scoped_match_result> m_default_matches;
	uint64_t m_num_loaded_policies;
};

class SINSP_PUBLIC syscall_policies : public matchlist_security_policies
{
public:
	syscall_policies();
	virtual ~syscall_policies();

	void init(security_mgr *mgr,
		  dragent_configuration *configuration,
		  sinsp *inspector);

	void reset();
	draiosproto::policy_type policies_type();
	draiosproto::policy_subtype policies_subtype();

	match_result *match_event(sinsp_evt *evt);

private:
	bool add_matchlist_details(security_policy *policy,
				   const draiosproto::matchlist_detail &details,
				   const scope_predicates &predicates,
				   std::string baseline_id,
				   const scope_predicates &baseline_predicates);

	inline bool is_baseline_requested(security_policy *policy)
	{
		return policy->has_baseline_details() && policy->baseline_details().syscall_enabled();
	}

	// Entry i in the vector is those policies that named event type i.
	std::vector<security_policies::scoped_match_result_list> m_event_index;

	// Maps from event name to list of ppm event numbers
	std::map<std::string,std::list<uint32_t>> m_evtnums;

	// Entry i in the vector is those policies that named syscall type i.
	std::vector<security_policies::scoped_match_result_list> m_syscall_index;

	// Maps from syscall name to syscall number
	std::map<std::string,uint32_t> m_syscallnums;

	const struct ppm_event_info *m_etable;
	const struct ppm_syscall_desc *m_stable;
};

//
// Each policy has sets of filterchecks and acceptable values along
// with match effects.
//
// For a given sinsp event, the entire set of loaded policies are
// considered. Each filter check value is extracted, compared to the
// list of values for the match list, and any non-matching match lists
// are removed. After all the filterchecks have been considered, the
// remaining matchlists are visited in order until the first terminal
// match effect is found. That policy is returned.
//

class SINSP_PUBLIC filtercheck_policies : public matchlist_security_policies
{
public:
	filtercheck_policies();
	virtual ~filtercheck_policies();

	virtual void init(security_mgr *mgr,
			  dragent_configuration *configuration,
			  sinsp *inspector);

	void reset();
	virtual draiosproto::policy_type policies_type() = 0;
	virtual draiosproto::policy_subtype policies_subtype() = 0;

	match_result *match_event(sinsp_evt *evt);

protected:

	virtual bool add_matchlist_details(security_policy *policy,
					   const draiosproto::matchlist_detail &details,
					   const scope_predicates &predicates,
					   std::string baseline_id,
					   const scope_predicates &baseline_predicates) = 0;

	virtual inline bool is_baseline_requested(security_policy *policy) = 0;

	// Allocate storage for the filter value specified by val/len
	// and return a filter_value using that allocated storage.
        filter_value_t add_filter_value(uint8_t *val, uint32_t len);

	vector<vector<uint8_t>> m_val_storages;

	// The event attribute to extract. This is used to find the
	// set of possible policies that match the event. For example,
	// all file opens of a given file.
	std::unique_ptr<sinsp_filter_check> m_check;

	// Maps from filtercheck value to match result. The policy and
	// match effect are filled in the result, but not the event
	// details.
	std::unordered_multimap<filter_value_t, security_policies::scoped_match_result, g_hash_membuf, g_equal_to_membuf> m_index;
};

class SINSP_PUBLIC net_inbound_policies : public matchlist_security_policies
{
public:
	net_inbound_policies();
	virtual ~net_inbound_policies();

	void init(security_mgr *mgr,
		  dragent_configuration *configuration,
		  sinsp *inspector);

	void reset();
	draiosproto::policy_type policies_type();
	draiosproto::policy_subtype policies_subtype();

	match_result *match_event(sinsp_evt *evt);

protected:
	bool add_matchlist_details(security_policy *policy,
				   const draiosproto::matchlist_detail &details,
				   const scope_predicates &predicates,
				   std::string baseline_id,
				   const scope_predicates &baseline_predicates);

	inline bool is_baseline_requested(security_policy *policy)
	{
		return policy->has_baseline_details() && policy->baseline_details().network_inoutbound_enabled();
	}

	std::string qualifies();

	security_policies::scoped_match_result_list m_index;
};

class SINSP_PUBLIC net_outbound_policies : public net_inbound_policies
{
public:
	net_outbound_policies();
	virtual ~net_outbound_policies();

	draiosproto::policy_type policies_type();
	draiosproto::policy_subtype policies_subtype();

protected:

	std::string qualifies();
};

class SINSP_PUBLIC tcp_listenport_policies : public filtercheck_policies
{
public:
	tcp_listenport_policies();
	virtual ~tcp_listenport_policies();

	void init(security_mgr *mgr,
		  dragent_configuration *configuration,
		  sinsp *inspector);

	draiosproto::policy_type policies_type();
	draiosproto::policy_subtype policies_subtype();

protected:
	bool add_matchlist_details(security_policy *policy,
				   const draiosproto::matchlist_detail &details,
				   const scope_predicates &predicates,
				   std::string baseline_id,
				   const scope_predicates &baseline_predicates);

	inline bool is_baseline_requested(security_policy *policy)
	{
		return policy->has_baseline_details() && policy->baseline_details().network_listening_enabled();
	}

	std::string qualifies();

	draiosproto::net_proto m_proto;
};

class SINSP_PUBLIC udp_listenport_policies : public tcp_listenport_policies
{
public:
	udp_listenport_policies();
	virtual ~udp_listenport_policies();

protected:
	std::string qualifies();
};

//
// Policies of this class use a prefix_map to compare events against matchlists
//
class SINSP_PUBLIC matchlist_map_security_policies : public matchlist_security_policies
{
public:
	matchlist_map_security_policies();
	virtual ~matchlist_map_security_policies();

	virtual void init(security_mgr *mgr,
			  dragent_configuration *configuration,
			  sinsp *inspector);

	void reset();
	virtual draiosproto::policy_type policies_type() = 0;
	virtual draiosproto::policy_subtype policies_subtype() = 0;

	match_result *match_event(sinsp_evt *evt);

	struct index_predicates
	{
		index_predicates(scope_predicates p,
				 scope_predicates bl_p,
				 bool h_s,
				 bool c_s)
			: preds(p),
			  host_scope(h_s),
			  container_scope(c_s)
		{
			if(bl_p.size() > 0)
			{
				preds.MergeFrom(bl_p);
			}
		}

		scope_predicates preds;
		bool host_scope;
		bool container_scope;
	};
	typedef struct index_predicates index_predicates_t;

protected:

	virtual std::string qualifies() = 0;

	typedef path_prefix_map<security_policies::match_result> path_matchresult_search;

	std::unique_ptr<sinsp_filter_check> m_check;

	bool add_matchlist_details(security_policy *policy,
				   const draiosproto::matchlist_detail &details,
				   const scope_predicates &predicates,
				   std::string baseline_id,
				   const scope_predicates &baseline_predicates);

	virtual inline bool is_baseline_requested(security_policy *policy) = 0;

	std::list<std::string> m_vals;

	// Empty match_lists message. Useful when wanting to return an
	// empty list in get_match_lists.
	draiosproto::match_lists m_empty_lists;

	// Given a filter value, break it into components suitable for prefix matching
	virtual void split_components(const filter_value_t &val, path_prefix_map_ut::filter_components_t &components) = 0;

	// From the provided matchlist_detail message, return the
	// appropriate match_lists message.
	virtual const draiosproto::match_lists &get_match_lists(const draiosproto::matchlist_detail &details) = 0;

	// Return whether or not the items in the given match list should be considered.
	virtual bool match_list_relevant(const draiosproto::match_list &list);

	// The set of paths are segregated across a number of different scopes.
	// Each scope has its own path_prefix_map.

	std::list<std::pair<index_predicates_t,std::vector<path_matchresult_search>>> m_index;

	// Given a scope, find the matching path_prefix_map to use,
	// creating it if necessary.
	path_matchresult_search &find_prefix_map(draiosproto::match_effect effect,
						 const scope_predicates &predicates,
						 const scope_predicates &baseline_predicates,
						 bool host_scope,
						 bool container_scope);

};

class SINSP_PUBLIC readonly_fs_policies : public matchlist_map_security_policies
{
public:
	readonly_fs_policies();
	virtual ~readonly_fs_policies();

	void init(security_mgr *mgr,
		  dragent_configuration *configuration,
		  sinsp *inspector);

	draiosproto::policy_type policies_type();
	draiosproto::policy_subtype policies_subtype();

protected:

	inline bool is_baseline_requested(security_policy *policy)
	{
		return policy->has_baseline_details() && policy->baseline_details().fs_read_only_enabled();
	}

	std::string qualifies();

	void split_components(const filter_value_t &val, path_prefix_map_ut::filter_components_t &components);

	const draiosproto::match_lists &get_match_lists(const draiosproto::matchlist_detail &details);

	bool match_list_relevant(const draiosproto::match_list &list);

	draiosproto::path_access_type m_access_type;
};

class SINSP_PUBLIC readwrite_fs_policies : public readonly_fs_policies
{
public:
	readwrite_fs_policies();
	virtual ~readwrite_fs_policies();

	draiosproto::policy_subtype policies_subtype();

protected:
	inline bool is_baseline_requested(security_policy *policy)
	{
		return policy->has_baseline_details() && policy->baseline_details().fs_read_write_enabled();
	}

	std::string qualifies();
};

// Slight abuse to use a namespace really from the sysdig repo
namespace path_prefix_map_ut
{
	void split_container_image(const filter_value_t &image,
				   filter_value_t &hostname,
				   filter_value_t &port,
				   filter_value_t &imagename,
				   filter_value_t &tag,
				   filter_value_t &digest);
}

class SINSP_PUBLIC container_policies : public matchlist_map_security_policies
{
public:
	container_policies();
	virtual ~container_policies();

	void init(security_mgr *mgr,
		  dragent_configuration *configuration,
		  sinsp *inspector);

	draiosproto::policy_type policies_type();
	draiosproto::policy_subtype policies_subtype();

protected:

	inline bool is_baseline_requested(security_policy *policy)
	{
		// at least for V1, baselines don't have information about container images
		// since are solely created based on a single container image
		return false;
	}

	void split_components(const filter_value_t &val, path_prefix_map_ut::filter_components_t &components);

	const draiosproto::match_lists &get_match_lists(const draiosproto::matchlist_detail &details);

	std::string qualifies();
};

class SINSP_PUBLIC process_policies : public filtercheck_policies
{
public:
	process_policies();
	virtual ~process_policies();

	void init(security_mgr *mgr,
		  dragent_configuration *configuration,
		  sinsp *inspector);

	draiosproto::policy_type policies_type();
	draiosproto::policy_subtype policies_subtype();

private:
	bool add_matchlist_details(security_policy *policy,
				   const draiosproto::matchlist_detail &details,
				   const scope_predicates &predicates,
				   std::string baseline_id,
				   const scope_predicates &baseline_predicates);

	inline bool is_baseline_requested(security_policy *policy)
	{
		return policy->has_baseline_details() && policy->baseline_details().process_enabled();
	}
};
#endif // CYGWING_AGENT
