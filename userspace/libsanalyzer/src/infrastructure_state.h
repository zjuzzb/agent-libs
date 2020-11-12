#ifndef CYGWING_AGENT
#ifndef INFRASTRUCTURE_STATE_H
#define INFRASTRUCTURE_STATE_H

#include <map>
#include <set>

#include "sinsp.h"
#include "sinsp_int.h"
#include "sinsp_errno.h"
#include "sinsp_signal.h"
#include "analyzer_utils.h"
#include "analyzer_settings.h"
#include "coclient.h"
#include "k8s_limits.h"
#include "sdc_internal.pb.h"
#include "type_config.h"
#include "k8s_namespace_store.h"
#include "k8s_store_manager.h"
#include "k8s_hpa_store.h"
#include "k8s_pod_store.h"

#include <gtest/gtest_prod.h>

namespace std
{
	template<>
	struct less<draiosproto::pod_status_count>
	{
		bool operator()(const draiosproto::pod_status_count &l, const draiosproto::pod_status_count &r) const
		{
			return l.status() < r.status();
		}
	};
}

typedef google::protobuf::RepeatedPtrField<draiosproto::scope_predicate> scope_predicates;
typedef google::protobuf::RepeatedPtrField<draiosproto::container_group> container_groups;

// An abstract-only class representing the interface used by clients
// of infrastructure_state

class infrastructure_state_iface
{
public:
	// <kind, UID> strings
	using uid_t = std::pair<std::string, std::string>;
	using reg_id_t = std::string;

	virtual void clear_scope_cache() = 0;

	/// Find list of key-value tags present in infrastructure_state
	/// \param uid  UID of the starting node of the graph
	/// \param tags_set  Set of tags we are looking for
	/// \param labels  Populated key/value map containing found tags
	/// \return
	virtual int find_tag_list(uid_t uid, std::unordered_set<string> &tags_set, std::unordered_map<string, string> &labels) const = 0;

	// Return the cluster name that must be set
	// for the orch state. This is what will be
	// displayed on the front end.
	virtual std::string get_k8s_cluster_name() = 0;

	// Return the k8s pod UID from namespace and pod name
	virtual std::string get_k8s_pod_uid(const std::string &namespace_name, const std::string &pod_name) const = 0;

	virtual bool find_tag(const uid_t& uid, const std::string& tag, std::string &value) const = 0;

	virtual int get_tags(uid_t uid, std::unordered_map<string, string>& tags_map) const = 0;

	// Check the uid against the scope predicates in predicates
	// and return whether or not the uid matches the predicates.
	virtual bool match_scope(const uid_t &uid, const scope_predicates &predicates) = 0;

	// Register a set of scope predicates with this object and
	// keep track of whether the predicates match the current
	// state. This is most interesting for container-level scope,
	// where the predicates are re-tested as containers come and go.
	//
	// Returns true if the scope could be registered, false otherwise.
	virtual bool register_scope(reg_id_t &reg,
				    bool host_scope, bool container_scope,
				    const scope_predicates &predicates) = 0;

	// Check a previously registered scope to see if it matches
	// the current state
	virtual bool check_registered_scope(reg_id_t &reg) const = 0;

	virtual std::string get_machine_id() const = 0;

	virtual sinsp_container_info::ptr_t get_container_info(const std::string& container_id) = 0;
};

class event_scope;

class infrastructure_state : public infrastructure_state_iface
{
public:
	static const std::string CONTAINER_WAITING_METRIC_NAME;
	static const std::string CONTAINER_TERMINATED_METRIC_NAME;
	static const std::string CONTAINER_ID_TAG;
	static const std::string CONTAINER_STATUS_REASON_TAG;

	// { host/container id : {scope hash : scope match result} }
	using policy_cache_t = std::unordered_map<std::string, std::unordered_map<size_t, bool>>;

	// Pass a 4th optional argument to turn on m_k8s_subscribed for unit tests. Need to refactor.
	infrastructure_state(sinsp_analyzer& analyzer,
						 sinsp *inspector,
						 const std::string& rootdir,
						 const k8s_limits::sptr_t& the_k8s_limits,
						 bool force_k8s_subscribed = false);
	virtual ~infrastructure_state();

	void init(const std::string& machine_id, const std::string& host_tags);
	bool inited();

	static std::string as_string(const scope_predicates &predicates);

	void subscribe_to_k8s();

	bool subscribed();

	void refresh(uint64_t ts);

	bool match_scope(const uid_t &uid, const scope_predicates &predicates) override;

	std::shared_ptr<draiosproto::container_group> get_pod_owner(std::shared_ptr<draiosproto::container_group> const& cg);
	std::shared_ptr<draiosproto::container_group> match_from_addr(const std::string &addr,
								      bool *found);

	bool is_k8s_cidr_discovered()
	{
		return !m_command_k8s_cluster_cidr.empty() &&
			!m_command_k8s_service_cidr.empty();
	}

	std::string get_command_k8s_cluster_cidr() const
	{
		return m_command_k8s_cluster_cidr;
	}

	std::string get_command_k8s_service_cidr() const
	{
		return m_command_k8s_service_cidr;
	}

	// Register a set of scope predicates with this object and
	// keep track of whether the predicates match the current
	// state. This is most interesting for container-level scope,
	// where the predicates are re-tested as containers come and go.
	//
	// Returns true if the scope could be registered, false otherwise.
	bool register_scope(reg_id_t &reg,
			    bool host_scope, bool container_scope,
			    const scope_predicates &predicates) override;

	// Check a previously registered scope to see if it matches
	// the current state
	bool check_registered_scope(reg_id_t &reg) const override;

	std::string get_machine_id() const override;

	sinsp_container_info::ptr_t get_container_info(const std::string& container_id) override;

	void calculate_rate_metrics(draiosproto::container_group *cg, const uint64_t ts);
	void delete_rate_metrics(const uid_t &key);

	void state_of(const std::vector<std::string> &container_ids, container_groups* state, const uint64_t ts);
	void state_of(const std::vector<std::string> &container_ids, draiosproto::k8s_state* state, const uint64_t ts);

	/** Returns all the discovered kubernetes congroups matching a given kind
	 *
	 * \param cgs  Populated container_groups retrieved
	 * \param kind Kubernetes Kind in the form of k8s_*
	 *             (e.g. k8s_endpoints, k8s_service, etc.)
	 */
	void get_congroups_by_kind(std::vector<std::shared_ptr<draiosproto::container_group>> *cgs, const string &kind) const;

	void get_state(container_groups* state, const uint64_t ts);
	void get_state(draiosproto::k8s_state* state, uint64_t ts);

	void on_new_container(const sinsp_container_info& container_info, sinsp_threadinfo *tinfo);
	void on_remove_container(const sinsp_container_info& container_info);

	void receive_hosts_metadata(const google::protobuf::RepeatedPtrField<draiosproto::congroup_update_event> &host_events);

	void clear_scope_cache() override;

	void load_single_event(const draiosproto::congroup_update_event &evt, bool overwrite = false);

	bool find_tag(const uid_t& uid, const std::string& tag, std::string &value) const override
	{
		std::unordered_set<uid_t> visited;
		return find_tag(uid, tag, value, visited);
	}

	bool match_name(const std::string &name, std::string *shortname = nullptr) const;

	typedef std::function<int(const draiosproto::container_group *cg, bool &stop)> cg_cb_t;
	int iterate_tree(bool scan_up, const uid_t &uid, cg_cb_t cg_cb) const
	{
		std::unordered_set<uid_t> visited;
		bool stop = false;
		return iterate_tree(scan_up, uid, cg_cb, stop, visited);
	}
	int iterate_tree(bool scan_up, const uid_t &uid, cg_cb_t cg_cb, bool &stop, std::unordered_set<uid_t> &visited) const;

	int iterate_parents(const uid_t &uid, cg_cb_t cg_cb) const
	{
		return iterate_tree(true, uid, cg_cb);
	}

	int iterate_children(const uid_t &uid, cg_cb_t cg_cb) const
	{
		return iterate_tree(false, uid, cg_cb);
	}

	typedef std::function<int(const std::pair<std::string, std::string> &tag, bool &stop)> tag_cb_t;
	int iterate_parent_tags(const uid_t &uid, tag_cb_t tag_cb) const;

	int find_tag_list(uid_t uid, std::unordered_set<string> &tags_set, std::unordered_map<string, string> &labels) const override
	{
		std::unordered_set<uid_t> visited;
		return find_tag_list(uid, tags_set, labels, visited);
	}
	int get_tags(uid_t uid, std::unordered_map<string, string>& tags_map) const override;
	// Get object names from object and its parents and add them to scope
	int get_scope_names(const uid_t &uid, event_scope *scope) const;

	void scrape_mesos_env(const sinsp_container_info& container, sinsp_threadinfo *tinfo);
	void get_orch_labels(const uid_t uid, google::protobuf::RepeatedPtrField<draiosproto::container_label>* labels, std::unordered_set<uid_t> *visited = nullptr);
	static bool is_mesos_label(const std::string &lbl);

	std::unique_ptr<draiosproto::container_group> get(uid_t uid);
	bool has(uid_t uid) const;
	unsigned int size();

	std::string get_k8s_cluster_name() override;
	// If the agent tags contain a tag for:
	// cluster:$NAME ; then extract $NAME and return it
	std::string get_cluster_name_from_agent_tags() const;
	// The UID of the default namespace is used as the cluster id
	std::string get_k8s_cluster_id() const;

	void add_annotation_filter(const std::string &ann);
	bool find_parent_kind(const uid_t &uid, const std::string &kind, uid_t &found_id) const;

	// Find our k8s node from our current container, any of the given container ids
	// or from IP address, in that order, if not found already
	void find_our_k8s_node(const std::vector<std::string> *container_ids);

	std::string get_k8s_pod_uid(const std::string &namespace_name, const std::string &pod_name) const override;

	// Return the container ID from the pod UID and the pod container name
	std::string get_container_id_from_k8s_pod_and_k8s_pod_name(const uid_t& p_uid, const std::string &pod_container_name) const;

	std::string get_parent_ip_address(const uid_t &uid) const;

	const std::string& get_k8s_url();
	const std::string& get_k8s_ca_certificate();
	const std::string& get_k8s_bt_auth_token();
	const std::string& get_k8s_ssl_certificate();
	const std::string& get_k8s_ssl_key();
	std::unordered_set<std::string> test_only_get_container_ids() const;

	bool find_local_ip(const std::string &ip, uid_t *uid) const;

private:
	FRIEND_TEST(infrastructure_state_test, connect_to_namespace);
	FRIEND_TEST(infrastructure_state_test, allowed_kinds_test);
	FRIEND_TEST(infrastructure_state_test, events_test);
	FRIEND_TEST(infrastructure_state_test, events_test_2);
	FRIEND_TEST(infrastructure_state_test, single_update);

	void configure_k8s_environment();

	// These return true if the new entry has been added, false if it already existed
	bool add(uid_t key);

	void emit(const draiosproto::container_group *grp, draiosproto::k8s_state *state, uint64_t ts);

	void resolve_names(draiosproto::k8s_state *state);

	void state_of(const draiosproto::container_group *grp,
		      container_groups* state,
		      std::unordered_set<uid_t>& visited, uint64_t ts);

	void state_of(const draiosproto::container_group *grp,
		      draiosproto::k8s_state *state,
		      std::unordered_set<uid_t>& visited, uint64_t ts);

	bool find_tag(const uid_t& uid, const std::string& tag, std::string &value, std::unordered_set<uid_t> &visited) const;
	int find_tag_list(uid_t uid, std::unordered_set<string> &tags_set, std::unordered_map<string,string> &labels, std::unordered_set<uid_t> &visited) const;
	bool walk_and_match(draiosproto::container_group *congroup,
			    scope_predicates &preds,
			    std::unordered_set<uid_t> &visited_groups);

	void update_parent_child_links(const uid_t& uid);

	void handle_event(const draiosproto::congroup_update_event *evt, bool overwrite = false);

	void handle_cluster_cidr(const draiosproto::container_group& congroup);

	void refresh_hosts_metadata();

	void add(uid_t &key, const draiosproto::container_group &cg);
	void update_metadata(uid_t &key, const draiosproto::container_group &cg);

	void connect_to_namespace(const infrastructure_state::uid_t& key);
	void connect_orphans();

	void connect(const infrastructure_state::uid_t& key);

	// Remove given key. Set update to true if the key will be reinstantiated as part of an update
	void remove(infrastructure_state::uid_t& key, bool update = false);
	// Discend into a cg children list recursively for removeing the cg as a parent.
	void remove_parent_recursively(const uid_t& what_uid, const uid_t& from_uid);
	bool has_link(const google::protobuf::RepeatedPtrField<draiosproto::congroup_uid>& links, const uid_t& uid);

	bool get_cached_result(const std::string &entity_id, size_t h, bool *res);
	void insert_cached_result(const std::string &entity_id, size_t h, bool res);
	void clear_cached_result(const std::string &entity_id);

	void add_ip_mappings(std::shared_ptr<draiosproto::container_group> cg);
	void remove_ip_mappings(std::shared_ptr<draiosproto::container_group> cg);

	void reset();

	void print_state() const;
	void print_obj(const uid_t &key) const;

	void connect_to_k8s(uint64_t ts = sinsp_utils::get_current_time_ns());
	void k8s_generate_user_event(const bool success);

	bool is_valid_for_export(const draiosproto::container_group *grp) const;

	void purge_tags_and_copy(uid_t, const draiosproto::container_group& cg);

	bool match_scope_all_containers(const scope_predicates &predicates);

	std::function<void(const draiosproto::congroup_update_event *evt)> m_handle_update_event;
	void handle_update_event_thin_cointerface(const draiosproto::congroup_update_event *evt);
	void handle_update_event_no_thin_cointerface(const draiosproto::congroup_update_event *evt);
	bool kind_is_allowed(const std::string& kind) const;
	void dump_memory_info() const;
	std::map<uid_t, uint32_t> get_duplicated_link(const google::protobuf::RepeatedPtrField<draiosproto::congroup_uid>& links) const;

	std::map<uid_t, std::shared_ptr<draiosproto::container_group>> m_state;

	std::unordered_map<std::string, std::unordered_set<std::shared_ptr<draiosproto::container_group>>> m_cg_by_addr;
	std::unordered_map<uid_t, uint64_t> m_cg_ttl;
	std::string m_command_k8s_cluster_cidr;
	std::string m_command_k8s_service_cidr;

	using pod_status_set_t = std::set<draiosproto::pod_status_count, std::less<draiosproto::pod_status_count>>;
	std::map<std::string, pod_status_set_t> m_pod_status;
	std::unordered_map<uid_t, std::vector<uid_t>> m_orphans;
	std::unordered_map<uid_t, std::unordered_set<uid_t>> m_parents;
	k8s_namespace_store m_k8s_namespace_store;
	k8s_store_manager m_k8s_store_manager;

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

	sinsp_analyzer& m_analyzer;
	sinsp *m_inspector;
	std::string m_machine_id;
	uint64_t m_ts;

	std::hash<std::string> m_str_hash_f;

	std::unique_ptr<coclient> m_k8s_coclient;
	coclient::response_cb_t m_k8s_callback;
	bool m_k8s_subscribed;   // True if we're supposed to connect to k8s
	bool m_k8s_connected;    // True if we have an active RPC connection
	const k8s_limits::sptr_t m_k8s_limits;
	mutable std::string m_k8s_cached_cluster_id;
	run_on_interval m_k8s_refresh_interval;
	run_on_interval m_k8s_connect_interval;
	run_on_interval m_delayed_removal_interval;

	int m_k8s_prev_connect_state;
	std::string m_k8s_node;
	std::string m_k8s_node_uid;
	bool m_k8s_node_actual;	// True if node found from following a running container

	struct rate_metric_state_t {
		rate_metric_state_t() : val(0), ts(0), last_rate(0) {}
		double val;
		time_t ts;
		double last_rate;
	};

	std::unordered_map<uid_t, std::unordered_map<std::string, rate_metric_state_t>> m_rate_metric_state;
	std::unordered_map<std::string, rate_metric_state_t> m_pod_restart_rate;
	static double calculate_rate(rate_metric_state_t& prev, double value, uint64_t ts);

	std::set<std::string> m_annotation_filter;

	std::string m_root_dir;

	// the config value, c_k8s_url, only represents what we get out of the
	// config. We do some post processing to get the value we actually use and store
	// it here.
	std::string m_k8s_url;
	std::string m_k8s_bt_auth_token;
	std::string m_k8s_ca_certificate;
	std::string m_k8s_ssl_certificate;
	std::string m_k8s_ssl_key;
	// Local cache for k8s_cluster_name
	std::string m_k8s_cluster_name;
	std::set<std::string> m_allow_list_kinds;

private:
	/**
	 * adjusts path for changes in configured root dir
	 */
	std::string normalize_path(const std::string& path) const;
public:
	// These are name tags as sent from cointerface
	// Make sure this list is up to date, at least for those objects that
	// need to be added to event scopes or promscrape

	const std::unordered_map<std::string, std::string> m_name_map =
	{
		{"kubernetes.daemonSet.name",	"daemonset"},
		{"kubernetes.deployment.name",	"deployment"},
		{"kubernetes.hpa.name",		"hpa"},
		{"kubernetes.namespace.name",	"namespace"},
		{"kubernetes.node.name",	"node"},
		{"kubernetes.pod.name",		"pod"},
		{"kubernetes.replicaSet.name",	"replicaset"},
		{"kubernetes.replicationController.name",	"replicationcontroller"},
		{"kubernetes.resourcequota.name",   "resourcequota"},
		{"kubernetes.service.name",	"service"},
		{"kubernetes.statefulset.name",	"statefulset"}
	};

public: // configs
	static type_config<uint32_t> c_orchestrator_queue_len;
	static type_config<int32_t> c_orchestrator_gc;
	static type_config<uint32_t> c_orchestrator_informer_wait_time_s;
	static type_config<uint32_t> c_orchestrator_tick_interval_ms;
	static type_config<uint32_t> c_orchestrator_low_ticks_needed;
	static type_config<uint32_t> c_orchestrator_low_event_threshold;
	static type_config<bool> c_orchestrator_filter_empty;
	static type_config<uint32_t> c_orchestrator_batch_messages_queue_length;
	static type_config<uint32_t> c_orchestrator_batch_messages_tick_interval_ms;
	static type_config<bool> c_k8s_ssl_verify_certificate;
	static type_config<std::vector<std::string>> c_k8s_include_types;
	static type_config<std::vector<std::string>> c_k8s_pod_status_wl;
	static type_config<bool> c_k8s_terminated_pods_enabled;
	static type_config<uint32_t> c_k8s_event_counts_log_time;
	static type_config<uint64_t> c_k8s_timeout_s;
	static type_config<std::string>::ptr c_k8s_ssl_key_password;
	static type_config<std::string> c_k8s_ssl_certificate_type;
	static type_config<bool> c_k8s_autodetect;
	static type_config<uint64_t> c_k8s_refresh_interval;
	static type_config<uint32_t>::ptr c_k8s_max_rnd_conn_delay;
	static type_config<bool>::ptr c_thin_cointerface_enabled;
	static type_config<uint64_t> c_congroup_ttl_s;
	static type_config<std::vector<std::string>> c_pod_prefix_for_cidr_retrieval;
	static type_config<std::vector<std::string>>::ptr c_k8s_allow_list_kinds;

private: // configs which have non-static fields that we actually use. You probably don't
	 // want these. In almost all cases, you'll probably want to use the normalized
	 // member variables.
	static type_config<std::string> c_k8s_url;
	static type_config<std::string> c_k8s_bt_auth_token;
	static type_config<std::string> c_k8s_ca_certificate;
	static type_config<std::string> c_k8s_ssl_certificate;
	static type_config<std::string> c_k8s_ssl_key;

	static const string POD_STATUS_PHASE_LABEL;
	static const string UNSCHEDULABLE_TAG;
	friend class new_k8s_delegator;
	friend class test_helper;
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
