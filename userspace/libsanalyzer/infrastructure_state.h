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

	infrastructure_state(uint64_t refresh_interval);

	~infrastructure_state();

	void refresh();

	bool match(std::string &container_id,
			   const google::protobuf::RepeatedPtrField<draiosproto::scope_predicate> &scope_predicates);

	void state_of(const std::vector<std::string> &container_ids,
		std::vector<std::unique_ptr<draiosproto::container_group>>& state);

	void refresh_host_metadata(google::protobuf::RepeatedPtrField<draiosproto::congroup_update_event> &host_events);

private:

	std::unordered_set<string> host_children{
		"k8s_node",
		// other orchestrators nodes
	};

	void state_of(const draiosproto::container_group *grp,
		std::vector<std::unique_ptr<draiosproto::container_group>>& state,
		std::unordered_set<uid_t>& visited);

	bool walk_and_match(draiosproto::container_group *congroup,
						google::protobuf::RepeatedPtrField<draiosproto::scope_predicate> &preds,
						std::unordered_set<uid_t> &visited_groups);

	void handle_event(draiosproto::congroup_update_event *evt);

	void connect(infrastructure_state::uid_t& key);
	void remove(draiosproto::congroup_update_event *evt);

	void debug_print();

	state_t m_state;

	coclient m_coclient;
	coclient::response_cb_t m_callback;
	run_on_interval m_interval;

};

#endif // INFRASTRUCTURE_STATE_H
