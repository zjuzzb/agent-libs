#include "k8s_pod_store.h"
#include "common_logger.h"
#include <algorithm>


COMMON_LOGGER();

k8s_pod_store::k8s_pod_store()
{
}

k8s_pod_store::~k8s_pod_store()
{
}

void k8s_pod_store::add_pod(const uid_t& pod_uid, const std::string& ns, const std::string& node_name, label_set_t &&labels, port_names_t&& ports)
{
	m_pods.emplace(pod_uid, k8s_pod_store::pod(pod_uid, ns, node_name, std::move(labels), std::move(ports)));
}

void k8s_pod_store::add_service(const std::string &service_uid, const std::string& ns, selector_set_t &&selectors)
{
	service srv(service_uid, ns, std::move(selectors));
	m_services.emplace(std::make_pair(service_uid, std::move(srv)));
}

std::string k8s_pod_store::search_for_pod_parent_service(const std::string &pod_uid)
{
	std::string ret;
	auto pod_it = m_pods.find(pod_uid);

	if(pod_it == m_pods.end())
	{
		LOG_DEBUG("Pod uid %s not found in the cache", pod_uid.c_str());
	}
	else
	{
		for(auto& srv : m_services)
		{
			if(srv.second.serves_pod(pod_it->second))
			{
				LOG_DEBUG("Found matched service %s for pod %s"
					  , srv.first.c_str()
					  , pod_it->first.c_str());
				ret = srv.first;
				srv.second.add_matched_pod(pod_uid);
				break;
			}
		}
	}

	return ret;
}

std::vector<std::string> k8s_pod_store::search_for_service_children_pods(const std::string &service_uid)
{
	std::vector<std::string> ret;

	auto srv_it = m_services.find(service_uid);

	if(srv_it == m_services.end())
	{
		LOG_DEBUG("Service %s not found in chache", service_uid.c_str());
	}
	else
	{
		for(const auto& target_pod : m_pods)
		{
			if(srv_it->second.serves_pod(target_pod.second))
			{
				ret.push_back(target_pod.first);
				srv_it->second.add_matched_pod(target_pod.first);
			}
		}
	}

	return ret;
}

void k8s_pod_store::clear()
{
	m_pods.clear();
	m_services.clear();
	m_nodes.clear();
}

void k8s_pod_store::handle_add(const state_key_t& key, k8s_pod_store::state_t& state)
{
 	auto has_key = k8s_object_store::has_key(key, state);
	if(has_key.first)
	{
		auto &cg = *has_key.second->second.get();
		const std::string& kind = cg.uid().kind();

		if(kind == POD_KIND)
		{
			handle_add_pod(cg, state);
		}
		else if(kind == SERVICE_KIND)
		{
			handle_add_service(cg, state);
		}
		else if(kind == NODE_KIND)
		{
			handle_add_node(cg, state);
		}
	}
}

void k8s_pod_store::handle_update(const state_key_t& key, state_t& state)
{
	handle_delete(key, state);
	handle_add(key, state);
}

void k8s_pod_store::handle_delete(const state_key_t& key, state_t& state)
{
	auto has_key = k8s_object_store::has_key(key, state);
	if(has_key.first)
	{
		auto& pod_cg = *has_key.second->second.get();
		const std::string& kind = pod_cg.uid().kind();
		const std::string& id = pod_cg.uid().id();

		if(kind == POD_KIND)
		{
			m_pods.erase(id);

			// We are not going here to delete the actual pod cg from m_state.
			// For example may came from an UPDATE event, and infrastructure_state could handle
			// the event without removing the object
			// Therefore, we are going un unlink all the pod's services from m_state
 			for(auto pod_prt_it = pod_cg.mutable_parents()->begin(); pod_prt_it != pod_cg.mutable_parents()->end();)
			{
				if(pod_prt_it->kind() == k8s_pod_store::SERVICE_KIND)
				{
					auto prt_srv_id = pod_prt_it->id();
					pod_prt_it = pod_cg.mutable_parents()->erase(pod_prt_it);

					//Presumably this service has the pod as a child. Remove the child
					auto srv_it = state.find({k8s_pod_store::SERVICE_KIND, prt_srv_id});
					if(srv_it != state.end())
					{
						draiosproto::container_group& srv_cg = *srv_it->second.get();
						for(auto srv_child_it = srv_cg.mutable_children()->begin(); srv_child_it != srv_cg.mutable_children()->end();)
						{
							if(srv_child_it->id() == id)
							{
								srv_child_it = srv_cg.mutable_children()->erase(srv_child_it);
							}
							else
							{
								srv_child_it++;
							}
						}
					}
				}
				else
				{
					pod_prt_it++;
				}
			}

 		}
		else if(kind == SERVICE_KIND)
		{
			// Unlink pods
			auto it = m_services.find(id);
			if(it != m_services.end())
			{
				auto linked_pods = it->second.matched_pods();
				for(auto& pod_uid : linked_pods)
				{
					remove_service_from_pod(pod_uid, id, state);
				}
			}
			m_services.erase(id);
		}
	}
}

k8s_pod_store::label_set_t k8s_pod_store::get_labels_from_cg(const draiosproto::container_group& cg) const
{
	label_set_t labels;
	std::for_each(cg.tags().begin()
		      , cg.tags().end()
		      , [&labels](const std::pair<std::string, std::string> p)
			{
				// cointerface sends labels in the form kubernetes.pod.label.status.phase.
				// We are going to store status.phase
				auto pos = p.first.find(".label");
				if(pos != std::string::npos)
				{
					std::string key = p.first.substr(pos + std::string(".label.").size());
					labels.emplace(std::make_pair(key, p.second));
				}
			});
	return labels;
}

k8s_pod_store::pod::pod(const uid_t& id, const std::string& ns, const std::string& node_name, label_set_t&& labels, port_names_t&& ports)
	: m_id(id)
	, m_namespace(ns)
	, m_labels(std::move(labels))
	, m_port_names(std::move(ports))
	, m_node_name(node_name)
{
}

k8s_pod_store::pod::pod(k8s_pod_store::pod&& p)
	: m_id(p.m_id)
	, m_namespace(std::move(p.m_namespace))
	, m_labels(std::move(p.m_labels))
	, m_port_names(std::move(p.m_port_names))
	, m_node_name(std::move(p.m_node_name))
{
}

k8s_pod_store::pod::~pod()
{
}

const k8s_pod_store::label_set_t& k8s_pod_store::pod::labels() const
{
	return m_labels;
}

const k8s_pod_store::port_names_t& k8s_pod_store::pod::ports() const
{
	return m_port_names;
}

const std::string& k8s_pod_store::pod::node() const
{
	return m_node_name;
}

const std::string& k8s_pod_store::pod::namespace_() const
{
	return m_namespace;
}

k8s_pod_store::service::service(const std::string& uid, const std::string& ns, selector_set_t&& selectors)
	: m_uid(uid)
	, m_namespace(ns)
	, m_selectors(std::move(selectors))
{
}

k8s_pod_store::service::service(k8s_pod_store::service&& other)
	: m_uid(std::move(other.m_uid))
	, m_namespace(std::move(other.m_namespace))
	, m_selectors(std::move(other.m_selectors))
{
}

void k8s_pod_store::service::add_matched_pod(const std::string &uid)
{
	m_matched_pod.insert(uid);
}

k8s_pod_store::service::~service()
{
}

const std::set<std::string>& k8s_pod_store::service::matched_pods() const
{
	return m_matched_pod;
}

bool k8s_pod_store::service::serves_pod(const pod& target_pod)
{
	bool ret = true;
	if(target_pod.labels().size() == 0 || m_selectors.size() == 0)
	{
		ret = false;
	}
	else if(m_namespace != target_pod.namespace_())
	{
		ret = false;
	}
	else
	{
		label_set_t intersection;
		std::set_intersection(m_selectors.begin(),
		                      m_selectors.end(),
		                      target_pod.labels().begin(),
		                      target_pod.labels().end(),
		                      std::inserter(intersection, intersection.end()));

		ret = intersection.size() == m_selectors.size();
	}
	return ret;
}



const k8s_object_store::selector_set_t& k8s_pod_store::service::selectors() const
{
	return m_selectors;
}

k8s_pod_store::port_names_t k8s_pod_store::get_ports_from_cg(const draiosproto::container_group& cg) const
{
	port_names_t ret;
	for(const auto& port : cg.ports())
	{
		ret.emplace(port.name(), port.target_port());
	}
	return ret;
}

void k8s_pod_store::resolve_ports(draiosproto::container_group& cg, const std::vector<std::string>& matches) const
{
	ASSERT(cg.uid().kind() == k8s_pod_store::SERVICE_KIND);

	for(auto& port : *cg.mutable_ports())
	{
		uint32_t resolved_port = 0;

		if((port.has_target_port() && port.target_port() != 0)
		   || (!port.has_name() || port.name().empty()))
		{
			continue;
		}

		for(const auto& matched_pod : matches)
		{
			auto it = m_pods.find(matched_pod);
			ASSERT(it != m_pods.end());
			if(it != m_pods.end())
			{
				// look in this pod for a port with the same name
				auto port_it = it->second.ports().find(port.name());
				if(port_it != it->second.ports().end())
				{
					// Found. Get the port number
					resolved_port = port_it->second;
				}
			}
		}

		if(resolved_port != 0)
		{
			LOG_DEBUG("resolving port %s to %d", port.name().c_str(), resolved_port);
			port.set_target_port(resolved_port);
		}
		else
		{
			LOG_DEBUG("unable to resolve port %s", port.name().c_str());
		}
	}
}

void k8s_pod_store::handle_add_pod(draiosproto::container_group& cg, state_t& state)
{
	const std::string& id = cg.uid().id();
	add_pod(id, cg.namespace_(), cg.node(), get_labels_from_cg(cg), get_ports_from_cg(cg));

	//check for a match with services
	std::string srv_id = search_for_pod_parent_service(id);
	if(!srv_id.empty())
	{
		// That's a match
		LOG_DEBUG("Found service %s for pod %s", srv_id.c_str(), id.c_str());
		draiosproto::congroup_uid* parent = cg.mutable_parents()->Add();
		parent->set_kind(SERVICE_KIND);
		parent->set_id(srv_id);

		auto srv_it = state.find(std::make_pair(SERVICE_KIND, srv_id));
		if(srv_it != state.end())
		{
			draiosproto::container_group& srv_cg = *srv_it->second.get();
			auto child = srv_cg.mutable_children()->Add();
			child->set_kind(POD_KIND);
			child->set_id(id);
		}

	}

	// Look for the node id
	const std::string& pod_node_name = cg.node();

	auto pos = m_nodes.find(pod_node_name);

	if(pos != m_nodes.end())
	{
		LOG_DEBUG("Adding node parent %s to pod %s", pod_node_name.c_str(), id.c_str());
		auto parent = cg.mutable_parents()->Add();
		parent->set_id(pos->second);
		parent->set_kind(NODE_KIND);
	}
	else
	{
		LOG_DEBUG("Node %s is not in infrastructure state. Could not add parent to pod %s - %s", pod_node_name.c_str(), id.c_str()
			  , cg.DebugString().c_str());
	}
}

void k8s_pod_store::handle_add_service(draiosproto::container_group& cg, state_t& state)
{
	const auto& id = cg.uid().id();
	selector_set_t selectors;
	selectors.insert(cg.selectors().begin(), cg.selectors().end());
	add_service(id, cg.namespace_(),  std::move(selectors));

	// Look for matches in pods
	std::vector<std::string> matches = search_for_service_children_pods(id);
	resolve_ports(cg, matches);

	if(!matches.empty())
	{
		LOG_DEBUG("Found %ld pods for service %s", matches.size(), id.c_str());

		for(const auto& pod_id : matches)
		{
			auto it = state.find(std::make_pair(POD_KIND, pod_id));
			if(it == state.end())
			{
				// This shouldnt happen. So let's warning
				LOG_WARNING("Unable to find pod with id %s in the infrastructure state", pod_id.c_str());
			}
			else
			{
				draiosproto::container_group& srv_pod = *it->second.get();
				auto parent = srv_pod.mutable_parents()->Add();
				parent->set_id(id);
				parent->set_kind(SERVICE_KIND);
				LOG_DEBUG("Add service parent %s to child pod %s", id.c_str(), pod_id.c_str());

				draiosproto::congroup_uid* child = cg.mutable_children()->Add();
				child->set_kind(POD_KIND);
				child->set_id(pod_id);
				LOG_DEBUG("Add pod child %s to service %s", pod_id.c_str(), id.c_str());
			}
		}
	}
}

void k8s_pod_store::handle_add_node(draiosproto::container_group& cg, state_t& state)
{
	m_nodes[cg.node()] = cg.uid().id();

	// Look for pods living in this node
	for(auto& pod : m_pods)
	{
		if(pod.second.node() == cg.node())
		{
			auto it = state.find(std::make_pair(POD_KIND, pod.first));
			if(it == state.end())
			{
				LOG_DEBUG("Pod %s not found in infrastructure state", pod.first.c_str());
			}
			else
			{
				draiosproto::container_group& pod_cg = *it->second.get();
				auto parent = pod_cg.mutable_parents()->Add();
				parent->set_id(cg.uid().id());
				parent->set_kind(NODE_KIND);
				LOG_DEBUG("Add node %s to pod %s", cg.uid().id().c_str(), pod_cg.uid().id().c_str());
			}
		}
	}
}

void k8s_pod_store::remove_service_from_pod(const std::string& pod_id, const std::string& service_id, state_t& state)
{
	auto has_key = k8s_pod_store::has_key(std::make_pair(k8s_pod_store::POD_KIND, pod_id), state);
	if(has_key.first)
	{
		draiosproto::container_group& cg = *has_key.second->second.get();
		for(auto it = cg.mutable_parents()->begin(); it!= cg.mutable_parents()->end(); it++)
		{
			if(it->id() == service_id)
			{
				LOG_DEBUG("Removing service %s from pod %s", service_id.c_str(), cg.uid().id().c_str());
				cg.mutable_parents()->erase(it);
				break;
			}
		}
	}
	else
	{
		LOG_DEBUG("Cannot remove service %s from pod %s. Pod non found in state", service_id.c_str(), pod_id.c_str());
	}
}

uint64_t k8s_pod_store::size() const
{
	return 	m_pods.size() + m_services.size() + m_nodes.size();
}

void k8s_pod_store::print_store_status() const
{
	LOG_DEBUG("pods: %ld - services: %ld - nodes: %ld"
		  , m_pods.size()
		  , m_services.size()
		  , m_nodes.size());
}
