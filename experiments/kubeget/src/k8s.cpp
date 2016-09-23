//
// k8s.cpp
//

#include "k8s.h"
#include "k8s_component.h"
//#include "k8s_dispatcher.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include <sstream>
#include <utility>
#include <memory>
#include <algorithm>
#include <iostream>

k8s_component::type_map k8s::m_components;

k8s::k8s(const std::string& uri, bool is_captured,
#ifdef HAS_CAPTURE
		ssl_ptr_t ssl, bt_ptr_t bt,
#endif // HAS_CAPTURE
		filter_ptr_t event_filter,
		ext_list_ptr_t extensions) :
		m_state(is_captured),
		m_event_filter(event_filter)
#ifdef HAS_CAPTURE
		,m_net(uri.empty() ? 0 : new k8s_net(*this, m_state, uri, ssl, bt, extensions, event_filter))
#endif
{
	g_logger.log(std::string("Creating K8s object for [" +
							 (uri.empty() ? std::string("capture replay") : uri) + ']'),
							 sinsp_logger::SEV_DEBUG);
	if(m_components.empty())
	{
		m_components.insert({ k8s_component::K8S_NODES,                  "nodes"                  });
		m_components.insert({ k8s_component::K8S_NAMESPACES,             "namespaces"             });
		m_components.insert({ k8s_component::K8S_PODS,                   "pods"                   });
		m_components.insert({ k8s_component::K8S_REPLICATIONCONTROLLERS, "replicationcontrollers" });
		m_components.insert({ k8s_component::K8S_SERVICES,               "services"               });
		if(event_filter)
		{
			m_components.insert({ k8s_component::K8S_EVENTS, "events"});
		}
		if(extensions)
		{
			for(const auto& ext : *extensions)
			{
				if(ext == "daemonsets")
				{
					m_components.insert({ k8s_component::K8S_DAEMONSETS,  "daemonsets"  });
				}
				else if(ext == "deployments")
				{
					m_components.insert({ k8s_component::K8S_DEPLOYMENTS, "deployments" });
				}
				else if(ext == "replicasets")
				{
					m_components.insert({ k8s_component::K8S_REPLICASETS, "replicasets" });
				}
			}
		}
	}
}

k8s::~k8s()
{
	stop_watch();
	cleanup();
}

void k8s::stop_watch()
{
#ifdef HAS_CAPTURE
	if(m_net)
	{
		m_net->stop_watching();
	}
#endif
}

void k8s::cleanup()
{
#ifdef HAS_CAPTURE
	delete m_net;
	m_net = 0;
#endif
}

void k8s::check_components()
{
#ifdef HAS_CAPTURE
	if(m_net)
	{
		for (auto& component : m_components)
		{
			if(!m_net->has_handler(component))
			{
				if(component.first != k8s_component::K8S_EVENTS)
				{
					m_net->add_handler(component);
				}
				else if(m_event_filter) // events only if filter is enabled
				{
					m_net->add_handler(component);
				}
			}
		}
	}
	else
	{
		throw sinsp_exception("K8s net object is null.");
	}
#endif
}

const k8s_state_t& k8s::get_state()
{
	return m_state;
}

void k8s::watch()
{
#ifdef HAS_CAPTURE
	if(m_net)
	{
		check_components();
		m_net->watch();
	}
#endif
}

void k8s::simulate_watch_event(const std::string& json)
{
	Json::Value root;
	Json::Reader reader;
	k8s_component::type component_type = k8s_component::K8S_COMPONENT_COUNT;
	if(reader.parse(json, root, false))
	{
		Json::Value kind = root["kind"];
		if(!kind.isNull() && kind.isString())
		{
			std::string type = kind.asString();
			if(type == "Namespace")                  { component_type = k8s_component::K8S_NAMESPACES;             }
			else if(type == "Node")                  { component_type = k8s_component::K8S_NODES;                  }
			else if(type == "Pod")                   { component_type = k8s_component::K8S_PODS;                   }
			else if(type == "ReplicationController") { component_type = k8s_component::K8S_REPLICATIONCONTROLLERS; }
			else if(type == "ReplicaSet")            { component_type = k8s_component::K8S_REPLICASETS;            }
			else if(type == "Service")               { component_type = k8s_component::K8S_SERVICES;               }
			else if(type == "DaemonSet")             { component_type = k8s_component::K8S_DAEMONSETS;             }
			else if(type == "Deployment")            { component_type = k8s_component::K8S_DEPLOYMENTS;            }
			else if(type == "EventList")             { component_type = k8s_component::K8S_EVENTS;                 }
			else
			{
				g_logger.log("Unrecognized component type: " + type, sinsp_logger::SEV_ERROR);
				return;
			}
		}
		else
		{
			g_logger.log("Component type not found in JSON", sinsp_logger::SEV_ERROR);
			return;
		}
	}
	else
	{
		g_logger.log("Error parsing JSON", sinsp_logger::SEV_ERROR);
		return;
	}

	ASSERT(component_type < k8s_component::K8S_COMPONENT_COUNT);
	// TODO: for new data collection
	//m_dispatch[component_type]->extract_data(root, false);
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

	case k8s_component::K8S_REPLICASETS:
		return m_state.get_rss().size();

	case k8s_component::K8S_SERVICES:
		return m_state.get_services().size();

	case k8s_component::K8S_DAEMONSETS:
		return m_state.get_daemonsets().size();

	case k8s_component::K8S_DEPLOYMENTS:
		return m_state.get_deployments().size();

	case k8s_component::K8S_EVENTS:
		return m_state.get_events().size();

	case k8s_component::K8S_COMPONENT_COUNT:
	default:
		break;
	}

	std::ostringstream os;
	os << "Unknown component " << static_cast<int>(component);
	throw sinsp_exception(os.str());
}
