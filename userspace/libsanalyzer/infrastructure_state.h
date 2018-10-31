#ifndef CYGWING_AGENT
#ifndef INFRASTRUCTURE_STATE_H
#define INFRASTRUCTURE_STATE_H

#include <map>

#include "sinsp.h"
#include "sinsp_int.h"
#include "sinsp_errno.h"
#include "sinsp_signal.h"
#include "analyzer_utils.h"
#include "analyzer_settings.h"
#include "coclient.h"
#include "k8s_limits.h"

typedef google::protobuf::RepeatedPtrField<draiosproto::scope_predicate> scope_predicates;
typedef google::protobuf::RepeatedPtrField<draiosproto::container_group> container_groups;

class infrastructure_state
{
public:
	// <kind, UID> strings
	using uid_t = std::pair<std::string, std::string>;

	// { host/container id : {scope hash : scope match result} }
	using policy_cache_t = std::unordered_map<std::string, std::unordered_map<size_t, bool>>;

	infrastructure_state(uint64_t refresh_interval, sinsp *inspector, std::string install_prefix);
	using reg_id_t = std::string;

	~infrastructure_state();

	void init(const std::string& machine_id, bool prom_on);
	bool inited();

	static std::string as_string(const scope_predicates &predicates);

	void subscribe_to_k8s(string url, string ca_cert,
			      string client_cert, string client_key,
			      uint64_t timeout_s);

	bool subscribed();

	void refresh(uint64_t ts);

	// Check the uid against the scope predicates in predicates
	// and return whether or not the uid matches the predicates.
	bool match_scope(const uid_t &uid, const scope_predicates &predicates);

	// Register a set of scope predicates with this object and
	// keep track of whether the predicates match the current
	// state. This is most interesting for container-level scope,
	// where the predicates are re-tested as containers come and go.
	//
	// Returns true if the scope could be registered, false otherwise.
	bool register_scope(reg_id_t &reg,
			    bool host_scope, bool container_scope,
			    const scope_predicates &predicates);

	// Check a previously registered scope to see if it matches
	// the current state
	bool check_registered_scope(reg_id_t &reg);

	void state_of(const std::vector<std::string> &container_ids, container_groups* state);

	void get_state(container_groups* state);

	void on_new_container(const sinsp_container_info& container_info, sinsp_threadinfo *tinfo);
	void on_remove_container(const sinsp_container_info& container_info);

	void receive_hosts_metadata(const google::protobuf::RepeatedPtrField<draiosproto::congroup_update_event> &host_events);

	void clear_scope_cache();

	void load_single_event(const draiosproto::congroup_update_event &evt, bool overwrite = false);

	bool find_tag(uid_t uid, string tag, string &value) const
	{
		std::unordered_set<uid_t> visited;
		return find_tag(uid, tag, value, visited);
	}

	void scrape_mesos_env(const sinsp_container_info& container, sinsp_threadinfo *tinfo);
	void get_orch_labels(const uid_t uid, google::protobuf::RepeatedPtrField<draiosproto::container_label>* labels, std::unordered_set<uid_t> *visited = nullptr);
	static bool is_mesos_label(const std::string &lbl);

	std::unique_ptr<draiosproto::container_group> get(uid_t uid);
	bool has(uid_t uid) const;
	unsigned int size();

	std::string get_k8s_cluster_name() const;
	// The UID of the default namespace is used as the cluster id
	std::string get_k8s_cluster_id() const;
	void init_k8s_limits(filter_vec_t filters, bool log, uint16_t cache_size);

private:

	std::unordered_map<std::string, std::string> host_children {
		{"k8s_node", "kubernetes.node.name"}
		// other orchestrators nodes
	};

	// These return true if the new entry has been added, false if it already existed
	bool add(uid_t key);

	void state_of(const draiosproto::container_group *grp,
		      container_groups* state,
		      std::unordered_set<uid_t>& visited);

	bool find_tag(uid_t uid, string tag, string &value, std::unordered_set<uid_t> &visited) const;
	bool walk_and_match(draiosproto::container_group *congroup,
			    scope_predicates &preds,
			    std::unordered_set<uid_t> &visited_groups);

	void handle_event(const draiosproto::congroup_update_event *evt, bool overwrite = false);
	
	void refresh_hosts_metadata();

	void connect(infrastructure_state::uid_t& key);
	void remove(infrastructure_state::uid_t& key);
	bool has_link(const google::protobuf::RepeatedPtrField<draiosproto::congroup_uid>& links, const uid_t& uid);

	bool get_cached_result(const std::string &entity_id, size_t h, bool *res);
	void insert_cached_result(const std::string &entity_id, size_t h, bool res);

	void reset();

	void debug_print();

	void connect_to_k8s(uint64_t ts = sinsp_utils::get_current_time_ns());
	void k8s_generate_user_event(const bool success);

	bool is_valid_for_export(const draiosproto::container_group *grp) const;

	void purge_tags_and_copy(uid_t, const draiosproto::container_group& cg);

	bool match_scope_all_containers(const scope_predicates &predicates);

	std::map<uid_t, std::unique_ptr<draiosproto::container_group>> m_state;
	std::unordered_map<uid_t, std::vector<uid_t>> m_orphans;

	struct reg_scope_t {
		bool m_host_scope;
		bool m_container_scope;
		scope_predicates m_predicates;
		bool m_scope_match;
	};

	std::map<reg_id_t, reg_scope_t> m_registered_scopes;

	std::queue<draiosproto::congroup_update_event> m_host_events_queue;
	std::mutex m_host_events_queue_mutex;

	policy_cache_t m_policy_cache;

	sinsp *m_inspector;
	std::string m_machine_id;
	bool m_prom_enabled;

	std::hash<std::string> m_str_hash_f;

	coclient m_k8s_coclient;
	coclient::response_cb_t m_k8s_callback;
	string m_k8s_url;
	string m_k8s_ca_cert;
	string m_k8s_client_cert;
	string m_k8s_client_key;
	bool m_k8s_subscribed;   // True if we're supposed to connect to k8s
	bool m_k8s_connected;    // True if we have an active RPC connection
	k8s_limits m_k8s_limits;
	mutable std::string m_k8s_cached_cluster_id;
	run_on_interval m_k8s_refresh_interval;
	run_on_interval m_k8s_connect_interval;
	int m_k8s_prev_connect_state;
	string m_k8s_node;

	friend class new_k8s_delegator;
};

class new_k8s_delegator
{
public:
	new_k8s_delegator() : m_prev_deleg(false), m_cached_deleg(false) { }

	bool has_agent(infrastructure_state *, const infrastructure_state::uid_t uid, std::unordered_set<infrastructure_state::uid_t> *visited = nullptr);
	bool is_delegated_now(infrastructure_state *, int num_delegated);
	bool is_delegated(infrastructure_state *, int num_delegated, uint64_t);

private:
	bool m_prev_deleg;
	bool m_cached_deleg;

	run_on_interval m_delegation_interval = { K8S_DELEGATION_INTERVAL };
};

#endif // INFRASTRUCTURE_STATE_H
#endif // CYGWING_AGENT
