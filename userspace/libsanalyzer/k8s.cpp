//
// k8s.cpp
//


#include "k8s.h"
#include "k8s_component.h"
#include "k8s_dispatcher.h"
#include "draios.pb.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "google/protobuf/text_format.h"
#include <sstream>
#include <utility>
#include <memory>
#include <algorithm>
#include <iostream>


using namespace draiosproto;


const k8s_component::component_map k8s::m_components =
{
	{ k8s_component::K8S_NODES,                  "nodes"                  },
	{ k8s_component::K8S_NAMESPACES,             "namespaces"             },
	{ k8s_component::K8S_PODS,                   "pods"                   },
	{ k8s_component::K8S_REPLICATIONCONTROLLERS, "replicationcontrollers" },
	{ k8s_component::K8S_SERVICES,               "services"               }
};


k8s::dispatch_map k8s::make_dispatch_map(k8s_state_s& state)
{
	return dispatch_map
	{
		{ k8s_component::K8S_NODES,                  new k8s_dispatcher(k8s_component::K8S_NODES,                  state) },
		{ k8s_component::K8S_NAMESPACES,             new k8s_dispatcher(k8s_component::K8S_NAMESPACES,             state) },
		{ k8s_component::K8S_PODS,                   new k8s_dispatcher(k8s_component::K8S_PODS,                   state) },
		{ k8s_component::K8S_REPLICATIONCONTROLLERS, new k8s_dispatcher(k8s_component::K8S_REPLICATIONCONTROLLERS, state) },
		{ k8s_component::K8S_SERVICES,               new k8s_dispatcher(k8s_component::K8S_SERVICES,               state) }
	};
}


k8s::k8s(const std::string& uri, bool watch, const std::string& api) : m_net(*this, uri, api),
		m_watch(watch),
		m_proto(*new draiosproto::k8s_state),
		m_own_proto(true),
		m_dispatch(make_dispatch_map(m_state))
{
}

k8s::k8s(draiosproto::metrics& met,
	const std::string& uri,
	bool watch,
	const std::string& api) : m_net(*this, uri, api),
		m_watch(watch),
		m_proto(*met.mutable_kubernetes()),
		m_own_proto(false),
		m_dispatch(make_dispatch_map(m_state))
{
}

k8s::~k8s()
{
	if (m_watch)
	{
		m_net.stop_watching();
	}

	for (auto& update : m_dispatch)
	{
		delete update.second;
	}

	if (m_own_proto)
	{
		delete &m_proto;
	}
}

const draiosproto::k8s_state& k8s::get_proto()
{
	std::ostringstream os;
	for (auto& component : m_components)
	{
		m_state.clear(component.first);
		m_net.get_all_data(component, os);
		parse_json(os.str(), component);
		os.str("");
	}
	make_protobuf();
	if (m_watch && !m_net.is_watching())
	{
		m_net.start_watching();
	}
	return m_proto;
}

void k8s::on_watch_data(k8s_event_data&& msg)
{
	std::lock_guard<std::mutex> lock(m_mutex);
	m_dispatch[msg.component()]->enqueue(std::move(msg));
}

std::size_t k8s::count(k8s_component::type component) const
{
	switch (component)
	{
	case k8s_component::K8S_NODES:
		return m_state.get_nodes().size();

	case k8s_component::K8S_NAMESPACES:
		return m_state.get_namespaces().size();

	case k8s_component::K8S_PODS:
		return m_state.get_pods().size();

	case k8s_component::K8S_REPLICATIONCONTROLLERS:
		return m_state.get_rcs().size();

	case k8s_component::K8S_SERVICES:
		return m_state.get_services().size();

	case k8s_component::K8S_COMPONENT_COUNT:
	default:
		break;
	}

	std::ostringstream os;
	os << "Unknown component " << static_cast<int>(component);
	throw std::invalid_argument(os.str());
}

void k8s::extract_data(const Json::Value& items, k8s_component::type component)
{
	if (items.isArray())
	{
		std::lock_guard<std::mutex> lock(m_mutex);

		for (auto& item : items)
		{
			Json::Value obj = item["metadata"];
			if (obj.isObject())
			{
				Json::Value ns = obj["namespace"];
				std::string nspace;
				if (!ns.isNull())
				{
					nspace = ns.asString();
				}
				m_state.add_common_single_value(component, obj["name"].asString(), obj["uid"].asString(), nspace);

				Json::Value metadata = item["metadata"];
				if (!metadata.isNull())
				{
					std::vector<k8s_pair_s> entries = k8s_component::extract_object(metadata, "labels");
					if (entries.size() > 0)
					{
						m_state.replace_items(component, "labels", std::move(entries));
					}
				}

				Json::Value spec = item["spec"];
				if (!spec.isNull())
				{
					std::vector<k8s_pair_s> entries = k8s_component::extract_object(spec, "selector");
					if (entries.size() > 0)
					{
						m_state.replace_items(component, "selector", std::move(entries));
					}
				}

				if (component == k8s_component::K8S_NODES)
				{
					std::vector<std::string> addresses = k8s_component::extract_nodes_addresses(item["status"]);
					for (auto&& address : addresses)
					{
						m_state.add_last_node_ip(std::move(address));
					}
				}
				else if (component == k8s_component::K8S_PODS)
				{
					std::vector<std::string> containers = k8s_component::extract_pod_containers(item);
					m_state.get_pods().back().get_container_ids() = std::move(containers);
					k8s_component::extract_pod_data(item, m_state.get_pods().back());
				}
				else if (component == k8s_component::K8S_SERVICES)
				{
					k8s_component::extract_services_data(item["spec"], m_state.get_services().back());
				}
			}
		}
	}
}

void k8s::make_protobuf()
{
	for (auto& ns : m_state.get_namespaces())
	{
		populate_component(ns, m_proto.add_namespaces());
	}

	for (auto& node : m_state.get_nodes())
	{
		k8s_node* nodes = m_proto.add_nodes();
		populate_component(node, nodes);
		for (auto& host_ip : node.get_host_ips())
		{
			auto host_ips = nodes->add_host_ips();
			host_ips->assign(host_ip.begin(), host_ip.end());
		}
	}

	for (auto& pod : m_state.get_pods())
	{
		k8s_pod* pods = m_proto.add_pods();
		populate_component(pod, pods);
		for (auto& container_id : pod.get_container_ids())
		{
			auto container_ids = pods->add_container_ids();
			container_ids->assign(container_id.begin(), container_id.end());
		}
		const std::string& nn = pod.get_node_name();
		if (!nn.empty())
		{
			pods->set_node_name(nn);
		}
		const std::string& hip = pod.get_host_ip();
		if (!hip.empty())
		{
			pods->set_host_ip(hip);
		}
		const std::string& ip = pod.get_internal_ip();
		if (!ip.empty())
		{
			pods->set_internal_ip(ip);
		}
	}

	for (auto& rc : m_state.get_rcs())
	{
		populate_component(rc, m_proto.add_controllers());
	}

	for (auto& service : m_state.get_services())
	{
		k8s_service* services = m_proto.add_services();
		populate_component(service, services);
		services->set_cluster_ip(service.get_cluster_ip());
		for (auto& port : service.get_port_list())
		{
			k8s_service_net_port* p = services->add_ports();
			p->set_port(port.m_port);
			p->set_target_port(port.m_target_port);
			if (!port.m_protocol.empty())
			{
				p->set_protocol(port.m_protocol);
			}
			if (port.m_node_port)
			{
				p->set_node_port(port.m_node_port);
			}
		}
	}
}

void k8s::parse_json(const std::string& json, const k8s_component::component_map::value_type& component)
{
	Json::Value root;
	Json::Reader reader;
	if (reader.parse(json, root, false))
	{
		Json::Value items = root["items"];
		if (!root.isNull())
		{
			extract_data(items, component.first);
			//g_logger.log(root.toStyledString(), sinsp_logger::SEV_DEBUG);
		}
		else
		{
			throw std::invalid_argument("Invalid JSON");
		}
	}
	else
	{
		throw std::runtime_error("JSON parsing failed");
	}
}
