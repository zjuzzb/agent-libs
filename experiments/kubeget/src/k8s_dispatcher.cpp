//
// k8s_dispatcher.cpp
//

#include "k8s_dispatcher.h"
#include <assert.h>
#include <stdexcept>
#include <algorithm>
#include <sstream>
#include <iostream>

k8s_dispatcher::k8s_dispatcher(k8s_component::type t, k8s_state_s& state) :
	m_type(t),
	m_state(state)
{
}

void k8s_dispatcher::enqueue(k8s_event_data&& event_data)
{
	assert(event_data.component() == m_type);

	std::string&& data = event_data.data();

	if (m_messages.size() == 0)
	{
		m_messages.push_back("");
	}

	std::string* msg = &m_messages.back();
	std::string::size_type pos = msg->find_first_of('\n');
	
	// previous msg full, this is a beginning of new message
	if (pos != std::string::npos && pos == (msg->size() - 1))
	{
		m_messages.push_back("");
		msg = &m_messages.back();
	}

	while ((pos = data.find_first_of('\n')) != std::string::npos)
	{
		msg->append((data.substr(0, pos + 1)));
		data = data.substr(pos + 1);
		m_messages.push_back("");
		msg = &m_messages.back();
	};

	if (data.size() > 0)
	{
		msg->append((data));
	}

	dispatch(); // ?TODO: in separate thread?
}

bool k8s_dispatcher::is_valid(const std::string& msg)
{
	// zero-length message is valid because that's how it starts its life.
	// so, here we only check for messages that are single newline only
	// or those that are longer than one character and contain multiple newlines.

	if ((msg.size() == 1 && msg[0] == '\n') ||
		std::count(msg.begin(), msg.end(), '\n') > 1)
	{
		return false;
	}
	return true;
}

bool k8s_dispatcher::is_ready(const std::string& msg)
{
	// absurd minimum ( "{}\n" ) but it's hard to tell 
	// what minimal size is, so there
	if (msg.size() < 3) 
	{
		return false;
	}
	return msg[msg.size() - 1] == '\n';
}

k8s_dispatcher::msg_data k8s_dispatcher::get_msg_data(const Json::Value& root)
{
	msg_data data;
	Json::Value evtype = root["type"];
	if (!evtype.isNull())
	{
		const std::string& et = evtype.asString();
		if (!et.empty())
		{
			if      (et[0] == 'A') { data.m_reason = COMPONENT_ADDED;    }
			else if (et[0] == 'M') { data.m_reason = COMPONENT_MODIFIED; }
			else if (et[0] == 'D') { data.m_reason = COMPONENT_DELETED;  }
			else if (et[0] == 'E') { data.m_reason = COMPONENT_ERROR;    }
		}
		else
		{
			return msg_data();
		}
	}
	Json::Value object = root["object"];
	if (!object.isNull() && object.isObject())
	{
		Json::Value meta = object["metadata"];
		if (!meta.isNull() && meta.isObject())
		{
			Json::Value name = meta["name"];
			if (!name.isNull())
			{
				data.m_name = name.asString();
			}
			Json::Value uid = meta["uid"];
			if (!uid.isNull())
			{
				data.m_uid = uid.asString();
			}
			Json::Value nspace = meta["namespace"];
			if (!nspace.isNull())
			{
				data.m_namespace = nspace.asString();
			}
		}
	}
	return data;
}

void k8s_dispatcher::handle_node(const Json::Value& root, const msg_data& data)
{
	if (data.m_reason == COMPONENT_ADDED || data.m_reason == COMPONENT_MODIFIED)
	{
		std::cout << "NODE,";
		std::vector<std::string> addresses = k8s_component::extract_nodes_addresses(root["status"]);
		k8s_node_s& node = m_state.get_component<k8s_state_s::nodes, k8s_node_s>(m_state.get_nodes(), data.m_name, data.m_uid);
		if (addresses.size() > 0)
		{
			node.get_host_ips() = std::move(addresses);
		}
		Json::Value object = root["object"];
		if (!object.isNull())
		{
			Json::Value metadata = object["metadata"];
			if (!metadata.isNull())
			{
				k8s_pair_list entries = k8s_component::extract_object(metadata, "labels");
				if (entries.size() > 0)
				{
					node.get_labels() = std::move(entries);
				}
			}
		}
	}
	else if (data.m_reason == COMPONENT_DELETED)
	{
		if (!m_state.delete_component(m_state.get_nodes(), data.m_uid))
		{
			// log warning: node not found
		}
	}
	else // COMPONENT_ERROR
	{
		// log error
	}
}

void k8s_dispatcher::handle_namespace(const Json::Value& root, const msg_data& data)
{
	if (data.m_reason == COMPONENT_ADDED || data.m_reason == COMPONENT_MODIFIED)
	{
		std::cout << "NAMESPACE,";
		k8s_ns_s& node = m_state.get_component<k8s_state_s::namespaces, k8s_ns_s>(m_state.get_namespaces(), data.m_name, data.m_uid);
		Json::Value object = root["object"];
		if (!object.isNull())
		{
			Json::Value metadata = object["metadata"];
			if (!metadata.isNull())
			{
				k8s_pair_list entries = k8s_component::extract_object(metadata, "labels");
				if (entries.size() > 0)
				{
					node.get_labels() = std::move(entries);
				}
			}
		}
	}
	else if (data.m_reason == COMPONENT_DELETED)
	{
		if (!m_state.delete_component(m_state.get_namespaces(), data.m_uid))
		{
			// log warning: namespace not found
		}
	}
	else // COMPONENT_ERROR
	{
		// log error
	}
}

void k8s_dispatcher::handle_pod(const Json::Value& root, const msg_data& data)
{
	if (data.m_reason == COMPONENT_ADDED || data.m_reason == COMPONENT_MODIFIED)
	{
		std::cout << "POD,";
		Json::Value object = root["object"];
		if (!object.isNull())
		{
			k8s_pod_s& pod = m_state.get_component<k8s_state_s::pods, k8s_pod_s>(m_state.get_pods(), data.m_name, data.m_uid, data.m_namespace);
			Json::Value metadata = object["metadata"];
			if (!metadata.isNull())
			{
				k8s_pair_list entries = k8s_component::extract_object(metadata, "labels");
				if (entries.size() > 0)
				{
					pod.get_labels() = std::move(entries);
				}
			}
			std::vector<std::string> containers = k8s_component::extract_pod_containers(object);
			pod.get_container_ids() = std::move(containers);
			k8s_component::extract_pod_data(object, pod);
		}
	}
	else if (data.m_reason == COMPONENT_DELETED)
	{
		if (!m_state.delete_component(m_state.get_namespaces(), data.m_uid))
		{
			// log warning: namespace not found
		}
	}
	else // COMPONENT_ERROR
	{
		// log error
	}
}

void k8s_dispatcher::handle_rc(const Json::Value& root, const msg_data& data)
{
	if (data.m_reason == COMPONENT_ADDED || data.m_reason == COMPONENT_MODIFIED)
	{
		std::cout << "REPLICATION_CONTROLLER,";
		k8s_rc_s& rc = m_state.get_component<k8s_state_s::controllers, k8s_rc_s>(m_state.get_rcs(), data.m_name, data.m_uid, data.m_namespace);
		Json::Value object = root["object"];
		if (!object.isNull())
		{
			Json::Value metadata = object["metadata"];
			if (!metadata.isNull())
			{
				k8s_pair_list labels = k8s_component::extract_object(metadata, "labels");
				if (labels.size() > 0)
				{
					rc.get_labels() = std::move(labels);
				}
			}

			Json::Value spec = object["spec"];
			if (!spec.isNull())
			{
				k8s_pair_list selectors = k8s_component::extract_object(spec, "selector");
				if (selectors.size() > 0)
				{
					rc.get_labels() = std::move(selectors);
				}
			}
		}
	}
	else if (data.m_reason == COMPONENT_DELETED)
	{
		if (!m_state.delete_component(m_state.get_namespaces(), data.m_uid))
		{
			// log warning: namespace not found
		}
	}
	else // COMPONENT_ERROR
	{
		// log error
	}
}

void k8s_dispatcher::handle_service(const Json::Value& root, const msg_data& data)
{
	if (data.m_reason == COMPONENT_ADDED || data.m_reason == COMPONENT_MODIFIED)
	{
		std::cout << "SERVICE,";
		Json::Value object = root["object"];
		if (!object.isNull())
		{
			k8s_service_s& service = m_state.get_component<k8s_state_s::services, k8s_service_s>(m_state.get_services(), data.m_name, data.m_uid, data.m_namespace);
			Json::Value metadata = object["metadata"];
			if (!metadata.isNull())
			{
				k8s_pair_list entries = k8s_component::extract_object(metadata, "labels");
				if (entries.size() > 0)
				{
					service.get_labels() = std::move(entries);
				}
			}
			k8s_component::extract_services_data(object, service);
		}
	}
	else if (data.m_reason == COMPONENT_DELETED)
	{
		if (!m_state.delete_component(m_state.get_namespaces(), data.m_uid))
		{
			// log warning: namespace not found
		}
	}
	else // COMPONENT_ERROR
	{
		// log error
	}
}

void k8s_dispatcher::dispatch()
{
	for (list::iterator it = m_messages.begin(); it != m_messages.end();)
	{
		if (is_ready(*it))
		{
			Json::Value root;
			Json::Reader reader;
			if (reader.parse(*it, root, false))
			{
				msg_data data = get_msg_data(root);
				if (data.is_valid())
				{
					std::cout << '[' << to_reason_desc(data.m_reason) << ',';
					switch (m_type)
					{
						case k8s_component::K8S_NODES:
							handle_node(root, data);
							break;
						case k8s_component::K8S_NAMESPACES:
							handle_namespace(root, data);
							break;
						case k8s_component::K8S_PODS:
							handle_pod(root, data);
							break;
						case k8s_component::K8S_REPLICATIONCONTROLLERS:
							handle_rc(root, data);
							break;
						case k8s_component::K8S_SERVICES:
							handle_service(root, data);
							break;
						default:
						{
							std::ostringstream os;
							os << "Unknown component: " << static_cast<int>(m_type);
							throw std::invalid_argument(os.str());
						}
					}
					std::cout << data.m_name << ',' << data.m_uid << ',' << data.m_namespace << ']' << std::endl;
					//std::cout << std::endl << root.toStyledString() << std::endl;
				}
			}
			else
			{
				// TODO: bad notification - discard silently?
				std::cout << "Bad message received." << std::endl;
			}
			it = m_messages.erase(it);
		}
		else
		{
			++it;
		}
	}
}

