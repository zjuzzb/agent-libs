#ifndef INFRASTRUCTURE_STATE_H
#define INFRASTRUCTURE_STATE_H

#include <map>

#include "sinsp.h"
#include "sinsp_int.h"
#include "sinsp_errno.h"
#include "sinsp_signal.h"
#include "analyzer_utils.h"
#include "coclient.h"

class infrastructure_state
{
public:
	using uid_t = std::pair<std::string, std::string>;
	using state_t = std::map<uid_t, std::unique_ptr<draiosproto::container_group>>;

	using policy_cache_t = std::unordered_map<std::string, std::unordered_map<uint64_t, bool>>;

	infrastructure_state(uint64_t refresh_interval);

	~infrastructure_state();

	void init(sinsp *inspector, const std::string& machine_id);

	void subscribe_to_k8s(const string& url);

	bool subscribed();

	void refresh(uint64_t ts);

	bool match_scope(std::string &container_id, std::string &host_id, const draiosproto::policy &policy);

	void state_of(const std::vector<std::string> &container_ids, google::protobuf::RepeatedPtrField<draiosproto::container_group>* state);

	void get_state(google::protobuf::RepeatedPtrField<draiosproto::container_group>* state);

	void on_new_container(const sinsp_container_info& container_info);
	void on_remove_container(const sinsp_container_info& container_info);

	void receive_hosts_metadata(const google::protobuf::RepeatedPtrField<draiosproto::congroup_update_event> &host_events);

	void load_single_event(const draiosproto::congroup_update_event &evt, bool overwrite = false);

	std::unique_ptr<draiosproto::container_group> get(uid_t uid);
	bool has(uid_t uid);
	unsigned int size();

private:

	std::unordered_map<std::string, std::string> host_children {
		{"k8s_node", "kubernetes.node.name"}
		// other orchestrators nodes
	};

	void state_of(const draiosproto::container_group *grp,
		google::protobuf::RepeatedPtrField<draiosproto::container_group>* state,
		std::unordered_set<uid_t>& visited);

	bool walk_and_match(draiosproto::container_group *congroup,
						google::protobuf::RepeatedPtrField<draiosproto::scope_predicate> &preds,
						std::unordered_set<uid_t> &visited_groups);

	void handle_event(const draiosproto::congroup_update_event *evt, bool overwrite = false);

	void refresh_hosts_metadata();

	void connect(infrastructure_state::uid_t& key);
	void remove(infrastructure_state::uid_t& key);
	bool has_link(const google::protobuf::RepeatedPtrField<draiosproto::congroup_uid>& links, const uid_t& uid);

	void reset();

	void debug_print();

	state_t m_state;
	std::unordered_map<uid_t, std::vector<uid_t>> m_orphans;

	std::queue<draiosproto::congroup_update_event> m_host_events_queue;
	std::mutex m_host_events_queue_mutex;

	policy_cache_t m_container_p_cache;
	policy_cache_t m_host_p_cache;

	sinsp *m_inspector;
	std::string m_machine_id;

	coclient m_k8s_coclient;
	coclient::response_cb_t m_k8s_callback;
	string m_k8s_url;
	bool m_k8s_subscribed;
	run_on_interval m_k8s_interval;
};

#endif // INFRASTRUCTURE_STATE_H
