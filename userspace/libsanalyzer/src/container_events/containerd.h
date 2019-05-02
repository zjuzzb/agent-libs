#pragma once

#include <memory>
#include <string>
#include <vector>

#include "coclient.h"
#include "user_event.h"
#include "user_event_logger.h"
#include <container_events/containerd_events.grpc.pb.h>
#include <container_events/containerd_events.pb.h>

// containerd events can be listened to using the gRPC Subscribe method, which then
// returns a stream of Envelope objects, each describing a single event

// the event stream can be filtered by passing a list of strings to the Subscribe call
// the general syntax of each filter is: key1=="value1",key2=="value2" and all the
// conditions are ANDed together (we only use one condition per filter but we could
// also filter by e.g. namespace=="k8s.io"). All individual filters are ORed together,
// so by setting the filter to:
// - topic=="/container/create"
// - topic=="/tasks/exit"
// we subscribe to those two events

// On every flush in the main loop, sinsp_analyzer::emit_containerd_events() ensures that:
// - we have an instance of this class (we're connected to containerd's gRPC endpoint)
// - we have an active event subscription
// and then calls ->tick() to fetch new events over gRPC

class containerd_events {
public:
	typedef user_event_filter_t::ptr_t event_filter_ptr_t;

	explicit containerd_events(const std::string& containerd_sock, const std::string& machine_id, event_filter_ptr_t&& filter);
	void subscribe();
	void tick();
	inline bool is_open() const {
		return m_grpc_subscribe != nullptr;
	}

private:
	typedef void(containerd_events::* event_emitter_t)(containerd::services::events::v1::Envelope &, event_scope &);

	void handle_event(containerd::services::events::v1::Envelope& event);

	void emit_containers_create(containerd::services::events::v1::Envelope& event, event_scope& scope);
	void emit_images_create(containerd::services::events::v1::Envelope& event, event_scope& scope);
	void emit_images_update(containerd::services::events::v1::Envelope& event, event_scope& scope);
	void emit_images_delete(containerd::services::events::v1::Envelope& event, event_scope& scope);
	void emit_tasks_oom(containerd::services::events::v1::Envelope& event, event_scope& scope);
	void emit_tasks_exit(containerd::services::events::v1::Envelope& event, event_scope& scope);

	void emit_event(user_event_logger::severity severity, uint64_t ts, event_scope& scope, std::string& name, std::string& desc);

	std::unique_ptr<streaming_grpc_client(&containerd::services::events::v1::Events::Stub::AsyncSubscribe)> m_grpc_subscribe;

	std::string m_containerd_sock;
	std::vector<std::string> m_filters;
	std::string m_machine_id;
	event_filter_ptr_t m_event_filter;

	bool m_container_exit_filter;
	bool m_container_die_filter;

	static std::unordered_map<std::string, event_emitter_t> s_event_emitters;
};
