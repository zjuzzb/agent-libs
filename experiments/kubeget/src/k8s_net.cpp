//
// k8s_net.cpp
//

#ifdef HAS_CAPTURE

#include "k8s_net.h"
#include "k8s_component.h"
#include "k8s_node_handler.h"
#include "k8s_namespace_handler.h"
#include "k8s_pod_handler.h"
#include "k8s_replicationcontroller_handler.h"
#include "k8s_replicaset_handler.h"
#include "k8s_service_handler.h"
#include "k8s_daemonset_handler.h"
#include "k8s_deployment_handler.h"
#include "k8s_event_handler.h"
#include "k8s.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include <sstream>
#include <utility>
#include <memory>


k8s_net::k8s_net(k8s& kube, k8s_state_t& state, const std::string& uri,
	ssl_ptr_t ssl,
	bt_ptr_t bt,
	ext_list_ptr_t extensions,
	filter_ptr_t event_filter) : m_k8s(kube), m_state(state),
		m_uri(uri),
		m_ssl(ssl),
		m_bt(bt),
		m_stopped(true),
		m_extensions(extensions),
		m_event_filter(event_filter)
{
}

k8s_net::~k8s_net()
{
	cleanup();
}

void k8s_net::cleanup()
{
	stop_watching();
	m_handlers.clear();
}

void k8s_net::watch()
{
	for(auto it = m_handlers.cbegin(); it != m_handlers.cend();)
	{
		k8s_component::type comp_type = it->first;
		if(it->second)
		{
			if(it->second->connection_error())
			{
				if(k8s_component::is_critical(comp_type))
				{
					throw sinsp_exception("K8s: " + k8s_component::get_name(comp_type) + " connection error.");
				}
				else
				{
					g_logger.log("K8s: " + k8s_component::get_name(comp_type) + " connection error, removing component.",
						 sinsp_logger::SEV_WARNING);
					if(m_collector.has(it->second->handler()))
					{
						m_collector.remove(it->second->handler());
					}
					m_handlers.erase(it++);
					g_logger.log("K8s: " + k8s_component::get_name(comp_type) + " removed from watched endpoints.",
						 sinsp_logger::SEV_INFO);
				}
			}
			else
			{
				it->second->collect_data();
				++it;
			}
		}
		else
		{
			g_logger.log("K8s: " + k8s_component::get_name(comp_type) + " handler is null.",
						 sinsp_logger::SEV_WARNING);
			++it;
		}
	}
}

void k8s_net::stop_watching()
{
	if(!m_stopped)
	{
		m_stopped = true;
		m_collector.remove_all();
	}
}

bool k8s_net::has_dependency(const k8s_component::type_map::value_type& component)
{
	switch(component.first)
	{
		case k8s_component::K8S_NODES:
			return true;
		case k8s_component::K8S_NAMESPACES:
			{
				auto it = m_handlers.find(k8s_component::K8S_NODES);
				return it!= m_handlers.end() && it->second && it->second->is_state_built();
			}
		case k8s_component::K8S_PODS:
			{
				auto it = m_handlers.find(k8s_component::K8S_NAMESPACES);
				return it!= m_handlers.end() && it->second && it->second->is_state_built();
			}
		case k8s_component::K8S_REPLICATIONCONTROLLERS:
			{
				auto it = m_handlers.find(k8s_component::K8S_PODS);
				return it!= m_handlers.end() && it->second && it->second->is_state_built();
			}
		case k8s_component::K8S_SERVICES:
			{
				auto it = m_handlers.find(k8s_component::K8S_REPLICATIONCONTROLLERS);
				return it!= m_handlers.end() && it->second && it->second->is_state_built();
			}
		case k8s_component::K8S_REPLICASETS:
			{
				auto it = m_handlers.find(k8s_component::K8S_SERVICES);
				return it!= m_handlers.end() && it->second && it->second->is_state_built();
			}
		case k8s_component::K8S_DAEMONSETS:
			{
				auto it = m_handlers.find(k8s_component::K8S_REPLICASETS);
				return it!= m_handlers.end() && it->second && it->second->is_state_built();
			}
		case k8s_component::K8S_DEPLOYMENTS:
			{
				auto it = m_handlers.find(k8s_component::K8S_DAEMONSETS);
				return it!= m_handlers.end() && it->second && it->second->is_state_built();
			}
		case k8s_component::K8S_EVENTS:
			{
				auto it = m_handlers.find(k8s_component::K8S_SERVICES);
				return it!= m_handlers.end() && it->second && it->second->is_state_built();
			}
		case k8s_component::K8S_COMPONENT_COUNT:
		default:
			throw sinsp_exception("k8s_net::add_handler: invalid type: " +
								  component.second + " (" +
								  std::to_string(component.first) + ')');
	}
	return false;
}

void k8s_net::add_handler(const k8s_component::type_map::value_type& component)
{
	if(!has_handler(component))
	{
		if(has_dependency(component))
		{
			std::ostringstream os;
			os << m_uri.get_scheme() << "://" << m_uri.get_host();
			int port = m_uri.get_port();
			if(port) { os << ':' << port; }
			switch(component.first)
			{
				case k8s_component::K8S_NODES:
					m_handlers[component.first] = std::make_shared<k8s_node_handler>(m_state, m_collector, os.str(), "1.0", m_ssl, m_bt);
					break;
				case k8s_component::K8S_NAMESPACES:
					m_handlers[component.first] = std::make_shared<k8s_namespace_handler>(m_state, m_collector, os.str(), "1.0", m_ssl, m_bt);
					break;
				case k8s_component::K8S_PODS:
					m_handlers[component.first] = std::make_shared<k8s_pod_handler>(m_state, m_collector, os.str(), "1.0", m_ssl, m_bt);
					break;
				case k8s_component::K8S_REPLICATIONCONTROLLERS:
					m_handlers[component.first] = std::make_shared<k8s_replicationcontroller_handler>(m_state, m_collector, os.str(), "1.0", m_ssl, m_bt);
					break;
				case k8s_component::K8S_REPLICASETS:
					m_handlers[component.first] = std::make_shared<k8s_replicaset_handler>(m_state, m_collector, os.str(), "1.0", m_ssl, m_bt);
					break;
				case k8s_component::K8S_SERVICES:
					m_handlers[component.first] = std::make_shared<k8s_service_handler>(m_state, m_collector, os.str(), "1.0", m_ssl, m_bt);
					break;
				case k8s_component::K8S_DAEMONSETS:
					m_handlers[component.first] = std::make_shared<k8s_daemonset_handler>(m_state, m_collector, os.str(), "1.0", m_ssl, m_bt);
					break;
				case k8s_component::K8S_DEPLOYMENTS:
					m_handlers[component.first] = std::make_shared<k8s_deployment_handler>(m_state, m_collector, os.str(), "1.0", m_ssl, m_bt);
					break;
				case k8s_component::K8S_EVENTS:
					m_handlers[component.first] = std::make_shared<k8s_event_handler>(m_state, m_collector, os.str(), "1.0", m_ssl, m_bt, m_event_filter);
					break;
				case k8s_component::K8S_COMPONENT_COUNT:
				default:
					throw sinsp_exception("k8s_net::add_handler: invalid type: " +
										  component.second + " (" +
										  std::to_string(component.first) + ')');
			}
			g_logger.log("K8s: created " + k8s_component::get_name(component) + " handler.", sinsp_logger::SEV_INFO);
		}
		else
		{
			g_logger.log("K8s: component " + k8s_component::get_name(component) + " does not have dependencies populated yet.",
						 sinsp_logger::SEV_DEBUG);
		}
	}
	else
	{
		g_logger.log("K8s: component " + k8s_component::get_name(component) + " already exists.",
					 sinsp_logger::SEV_TRACE);
	}
}
#endif // HAS_CAPTURE
