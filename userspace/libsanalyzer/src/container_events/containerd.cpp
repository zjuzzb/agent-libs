#include "containerd.h"
#include "user_event_logger.h"

#include <unordered_map>

#include "analyzer_utils.h"

#include <container_events/containerd_container.pb.h>
#include <container_events/containerd_image.pb.h>
#include <container_events/containerd_task.pb.h>

using namespace containerd::services::events::v1;
using namespace containerd::events;
using namespace containerd::services::images::v1;

namespace {
const int CONTAINERD_EVENTS_CONNECT_TIMEOUT_MS = 1000;

// we trim docker/containerd container ids to 12 characters in metrics
// so match this in containerd events as well (also, extremely long
// container ids are unreadable in the UI)
std::string trim_container_id(const std::string& container_id)
{
	return container_id.substr(0, 12);
}
}

containerd_events::containerd_events(const std::string& containerd_sock, const std::string& machine_id, event_filter_ptr_t&& filter):
	m_containerd_sock(containerd_sock),
	m_machine_id(machine_id),
	m_event_filter(filter)
{
	m_filters.clear();

	bool no_filter = m_event_filter == nullptr || m_event_filter->allows_all();
	bool container_filter = no_filter || m_event_filter->allows_all("container");
	m_container_exit_filter = container_filter || m_event_filter->has("container", "exit");
	m_container_die_filter = container_filter || m_event_filter->has("container", "die");

	bool image_filter = no_filter || m_event_filter->allows_all("image");

	if(container_filter || m_event_filter->has("container", "create"))
	{
		m_filters.emplace_back("topic==\"/containers/create\"");
	}
	if(m_container_exit_filter || m_container_die_filter)
	{
		m_filters.emplace_back("topic==\"/tasks/exit\"");
	}
	if(container_filter || m_event_filter->has("container", "oom"))
	{
		m_filters.emplace_back("topic==\"/tasks/oom\"");
	}
	if(image_filter || m_event_filter->has("image", "create"))
	{
		m_filters.emplace_back("topic==\"/images/create\"");
	}
	if(image_filter || m_event_filter->has("image", "update"))
	{
		m_filters.emplace_back("topic==\"/images/update\"");
	}
	if(image_filter || m_event_filter->has("image", "delete"))
	{
		m_filters.emplace_back("topic==\"/images/delete\"");
	}
}

void containerd_events::subscribe()
{
	SubscribeRequest req;
	for (const auto& filter : m_filters)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "containerd event filter: %s", filter.c_str());
		req.add_filters(filter);
	}

	auto callback =
		[this](streaming_grpc::Status status, Envelope& envelope)
		{
			if(status == streaming_grpc::ERROR)
			{
				g_logger.format(sinsp_logger::SEV_ERROR, "Could not connect to containerd grpc");
			}
			else if(status == streaming_grpc::SHUTDOWN)
			{
				g_logger.format(sinsp_logger::SEV_ERROR, "containerd grpc shut down");
			}
			else
			{
				handle_event(envelope);
			}
		};
	auto grpc_stub = grpc_connect<Events::Stub>(m_containerd_sock, CONTAINERD_EVENTS_CONNECT_TIMEOUT_MS);

	if(grpc_stub)
	{
		m_grpc_subscribe = make_unique<streaming_grpc_client(&Events::Stub::AsyncSubscribe)>(grpc_stub);
		m_grpc_subscribe->do_rpc(req, callback);
	}
}

void containerd_events::tick()
{
	if (m_grpc_subscribe != nullptr)
	{
		m_grpc_subscribe->process_queue();
	}
}

void containerd_events::handle_event(Envelope &event)
{
	auto it = s_event_emitters.find(event.topic());
	if(it == s_event_emitters.end())
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "Got unknown containerd event: %s", event.DebugString().c_str());
		return;
	}

	event_scope scope;
	if(!m_machine_id.empty())
	{
		scope.add("host.mac", m_machine_id);
	}

	(this->*(it->second))(event, scope);
}

void containerd_events::emit_containers_create(Envelope& event, event_scope& scope)
{
	ContainerCreate details;
	bool ret = details.ParseFromString(event.event().value());
	if (!ret) {
		g_logger.format(sinsp_logger::SEV_ERROR, "Failed to parse event");
		return;
	}

	std::string container_id = trim_container_id(details.id());
	const std::string& container_image = details.image();

	scope.add("container.id", container_id);
	std::string name = "Container created";
	std::string desc = "namespace: " + event.namespace_() + "; ID: " + container_id + "; image: " + container_image;

	emit_event(user_event_logger::SEV_EVT_INFORMATION, event.timestamp().seconds(), scope, name, desc);
}

void containerd_events::emit_images_create(Envelope& event, event_scope& scope)
{
	ImageCreate details;
	bool ret = details.ParseFromString(event.event().value());
	if (!ret) {
		g_logger.format(sinsp_logger::SEV_ERROR, "Failed to parse event");
		return;
	}

	const std::string& image_name = details.name();

	std::string name = "Image created";
	std::string desc = "namespace: " + event.namespace_() + "; image: " + image_name;

	emit_event(user_event_logger::SEV_EVT_INFORMATION, event.timestamp().seconds(), scope, name, desc);
}

void containerd_events::emit_images_update(Envelope& event, event_scope& scope)
{
	ImageUpdate details;
	bool ret = details.ParseFromString(event.event().value());
	if (!ret) {
		g_logger.format(sinsp_logger::SEV_ERROR, "Failed to parse event");
		return;
	}

	const std::string& image_name = details.name();

	std::string name = "Image updated";
	std::string desc = "namespace: " + event.namespace_() + "; image: " + image_name;

	emit_event(user_event_logger::SEV_EVT_INFORMATION, event.timestamp().seconds(), scope, name, desc);
}

void containerd_events::emit_images_delete(Envelope& event, event_scope& scope)
{
	ImageDelete details;
	bool ret = details.ParseFromString(event.event().value());
	if (!ret) {
		g_logger.format(sinsp_logger::SEV_ERROR, "Failed to parse event");
		return;
	}

	const std::string& image_name = details.name();

	std::string name = "Image deleted";
	std::string desc = "namespace: " + event.namespace_() + "; image: " + image_name;

	emit_event(user_event_logger::SEV_EVT_INFORMATION, event.timestamp().seconds(), scope, name, desc);
}

void containerd_events::emit_tasks_oom(Envelope& event, event_scope& scope)
{
	TaskOOM details;
	bool ret = details.ParseFromString(event.event().value());
	if (!ret) {
		g_logger.format(sinsp_logger::SEV_ERROR, "Failed to parse event");
		return;
	}

	std::string container_id = trim_container_id(details.container_id());

	scope.add("container.id", container_id);
	std::string name = "Container out of memory";
	std::string desc = "namespace: " + event.namespace_() + "; ID: " + container_id;

	emit_event(user_event_logger::SEV_EVT_INFORMATION, event.timestamp().seconds(), scope, name, desc);
}

void containerd_events::emit_tasks_exit(Envelope& event, event_scope& scope)
{
	TaskExit details;
	bool ret = details.ParseFromString(event.event().value());
	if (!ret) {
		g_logger.format(sinsp_logger::SEV_ERROR, "Failed to parse event");
		return;
	}

	std::string container_id = trim_container_id(details.container_id());
	int exit_status = details.exit_status();
	user_event_logger::severity log_level = user_event_logger::SEV_EVT_INFORMATION;

	scope.add("container.id", container_id);
	std::string name = "Container exited";
	std::string desc = "namespace: " + event.namespace_() + "; ID: " + container_id;

	if (details.id() != details.container_id())
	{
		// ignore `task-exec` exits
		return;
	}

	if (exit_status == 0)
	{
		if (!m_container_exit_filter)
		{
			return;
		}
	}
	else
	{
		if (!m_container_die_filter)
		{
			return;
		}
		name = "Container died";
		desc += "; ExitCode = " + std::to_string(exit_status);
		log_level = user_event_logger::SEV_EVT_WARNING;
	}

	emit_event(log_level, event.timestamp().seconds(), scope, name, desc);
}

void containerd_events::emit_event(user_event_logger::severity severity, uint64_t ts, event_scope& scope, std::string& name, std::string& desc)
{
	sinsp_user_event::tag_map_t tags;
	tags["source"] = "containerd";

	auto evt = sinsp_user_event(
		ts,
		std::move(name),
		std::move(desc),
		std::move(scope.get_ref()),
		std::move(tags),
		severity);

	user_event_logger::log(evt, severity);

	if(g_logger.get_severity() >= sinsp_logger::SEV_TRACE)
	{
		g_logger.log("CRI EVENT: scheduled for sending\n" + evt.to_string(), sinsp_logger::SEV_TRACE);
	}
}

std::unordered_map<std::string, containerd_events::event_emitter_t> containerd_events::s_event_emitters({
	{"/containers/create", &containerd_events::emit_containers_create},
	{"/images/create",     &containerd_events::emit_images_create},
	{"/images/update",     &containerd_events::emit_images_update},
	{"/images/delete",     &containerd_events::emit_images_delete},
	{"/tasks/oom",         &containerd_events::emit_tasks_oom},
	{"/tasks/exit",        &containerd_events::emit_tasks_exit},
});

