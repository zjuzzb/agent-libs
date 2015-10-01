//
// k8s.cpp
//


#include "k8s.h"
#include "k8s_component.h"
#include "draios.pb.h"
#include "google/protobuf/text_format.h"
#include <strstream>
#include <utility>
#include <memory>
#include <iostream>


using namespace draiosproto;


const k8s_component::component_map k8s::m_components =
{
	{ k8s_component::K8S_NODES, "nodes" },
	{ k8s_component::K8S_NAMESPACES, "namespaces" },
	{ k8s_component::K8S_PODS, "pods" },
	{ k8s_component::K8S_REPLICATIONCONTROLLERS, "replicationcontrollers" },
	{ k8s_component::K8S_SERVICES, "services" }
};


k8s::k8s(const std::string& uri, const std::string& api) : m_net(uri, api),
		m_k8s_state(*new draiosproto::k8s_state),
		m_own_state(true)
{
	init();
}

k8s::k8s(draiosproto::metrics& met,
	const std::string& uri,
	const std::string& api) : m_net(uri, api),
		m_k8s_state(*met.mutable_kubernetes()),
		m_own_state(false)
{
	init();
}

k8s::~k8s()
{
	if (m_own_state)
	{
		delete &m_k8s_state;
	}
}

void k8s::init()
{
	//subscribe();
	//m_dispatch_thread.join();
}

const draiosproto::k8s_state& k8s::get_proto()
{
	std::ostringstream os;
	for (auto& component : m_components)
	{
		m_net.get_all_data(component, os);
		parse_json(os.str(), component);
		os.str("");
	}
	make_protobuf();
	return m_k8s_state;
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
	}

	throw Poco::InvalidAccessException(
		Poco::format("Unknown component [%d]", static_cast<int>(component)));
}

void k8s::add_object_entry(k8s_component::type component, const std::string& name, k8s_pair_s&& p)
{
	m_state.emplace_item(component, name, std::forward<k8s_pair_s>(p));
}

// extracts labels or selectors
void k8s::extract_object(k8s_component::type component, const Json::Value& object, const std::string& name)
{
	if (!object.isNull())
	{
		Json::Value entries = object[name];
		if (!entries.isNull())
		{
			Json::Value::Members members = entries.getMemberNames();
			for (auto& member : members)
			{
				Json::Value val = entries[member];
				if (!val.isNull())
				{
					add_object_entry(component, name, k8s_pair_s(member, val.asString()));
				}
			}
		}
	}
}

void k8s::extract_nodes_addresses(const Json::Value& status)
{
	if (!status.isNull())
	{
		Json::Value addresses = status["addresses"];
		if (!addresses.isNull())
		{
			for (auto& address : addresses)
			{
				if (address.isObject())
				{
					Json::Value::Members addr_list = address.getMemberNames();
					for (auto& entry : addr_list)
					{
						if (entry == "address")
						{
							Json::Value ip = address[entry];
							if (!ip.isNull())
							{
								m_state.add_last_node_ip(ip.asString());
							}
						}
					}
				}
			}
		}
	}
}

void k8s::extract_pods_data(const Json::Value& item)
{
	extract_pod_containers(item);

	Json::Value spec = item["spec"];
	if (!spec.isNull())
	{
		Json::Value node_name = spec["nodeName"];
		if (!node_name.isNull())
		{
			m_state.set_last_pod_node_name(node_name.asString());
		}
		Json::Value status = item["status"];
		if (!status.isNull())
		{
			Json::Value host_ip = status["hostIP"];
			if (!host_ip.isNull())
			{
				m_state.set_last_pod_host_ip(host_ip.asString());
			}
			Json::Value pod_ip = status["podIP"];
			if (!pod_ip.isNull())
			{
				m_state.set_last_pod_internal_ip(pod_ip.asString());
			}
		}
	}
}

void k8s::extract_pod_containers(const Json::Value& item)
{
	Json::Value spec = item["status"];
	if (!spec.isNull())
	{
		Json::Value containers = spec["containerStatuses"];
		if (!containers.isNull())
		{
			for (auto& container : containers)
			{
				Json::Value container_id = container["containerID"];
				if (!container_id.isNull())
				{
					m_state.add_last_pod_container_id(container_id.asString());
				}
			}
		}
	}
}

void k8s::add_common_single_value(k8s_component::type component, const std::string& name, const std::string& uid, const std::string& ns)
{
	m_state.add_common_single_value(component, name, uid, ns);
}

void k8s::extract_data(const Json::Value& items, k8s_component::type component)
{
	if (items.isArray())
	{
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
				add_common_single_value(component, obj["name"].asString(), obj["uid"].asString(), nspace);


				Json::Value metadata = item["metadata"];
				if (!metadata.isNull())
				{
					extract_object(component, metadata, "labels");
				}

				Json::Value spec = item["spec"];
				if (!metadata.isNull())
				{
					extract_object(component, spec, "selector");
				}

				if (component == k8s_component::K8S_NODES)
				{
					extract_nodes_addresses(item["status"]);
				}
				else if (component == k8s_component::K8S_PODS)
				{
					extract_pods_data(item);
				}
			}
		}
	}
}

void k8s::make_protobuf()
{
	for (auto& ns : m_state.get_namespaces())
	{
		populate_component(ns, m_k8s_state.add_namespaces(), k8s_component::K8S_NAMESPACES);
	}

	for (auto& node : m_state.get_nodes())
	{
		k8s_node* nodes = m_k8s_state.add_nodes();
		populate_component(node, nodes, k8s_component::K8S_NODES);
		for (auto& host_ip : node.get_host_ips())
		{
			auto host_ips = nodes->add_host_ips();
			host_ips->assign(host_ip.begin(), host_ip.end());
		}
	}

	for (auto& pod : m_state.get_pods())
	{
		k8s_pod* pods = m_k8s_state.add_pods();
		populate_component(pod, pods, k8s_component::K8S_PODS);
		for (auto& container_id : pod.get_container_ids())
		{
			auto container_ids = pods->add_container_ids();
			container_ids->assign(container_id.begin(), container_id.end());
		}
		pods->set_node_name(pod.get_node_name());
		pods->set_host_ip(pod.get_host_ip());
		pods->set_internal_ip(pod.get_internal_ip());
	}

	for (auto& rc : m_state.get_rcs())
	{
		populate_component(rc, m_k8s_state.add_controllers(), k8s_component::K8S_REPLICATIONCONTROLLERS);
	}

	for (auto& service : m_state.get_services())
	{
		populate_component(service, m_k8s_state.add_services(), k8s_component::K8S_SERVICES);
	}
}

void k8s::parse_json(const std::string& json, const k8s_component::component_map::value_type& component)
{
	Json::Value root;
	Json::Reader reader;
	if (reader.parse(json, root, false))
	{
		Json::Value items = root["items"];
		extract_data(items, component.first);
		//std::cout << std::endl << root.toStyledString() << std::endl;
	}
}
