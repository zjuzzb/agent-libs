#include "k8s_namespace_store.h"
#include "libsanalyzer_exceptions.h"
#include "logger.h"
#include "common_logger.h"

COMMON_LOGGER();

k8s_namespace_store::k8s_namespace::k8s_namespace(const std::string& name)
	: m_name(name)
	, m_uid("")
{
}

k8s_namespace_store::k8s_namespace::k8s_namespace(const std::string& name, const std::string& id)
	: m_name(name)
	, m_uid(id)
{
}

k8s_namespace_store::k8s_namespace::k8s_namespace(k8s_namespace&& ns)
	: m_name(std::move(ns.m_name))
	, m_uid(std::move(ns.m_uid))
	, m_orphans(std::move(ns.m_orphans))
{
}

k8s_namespace_store::k8s_namespace::~k8s_namespace() noexcept
{
}

std::string k8s_namespace_store::k8s_namespace::name() const
{
	return m_name;
}

std::string k8s_namespace_store::k8s_namespace::uid() const
{
	return m_uid;
}

void k8s_namespace_store::k8s_namespace::set_uid(const std::string& id)
{
	m_uid = id;
}

bool k8s_namespace_store::k8s_namespace::has_orphans() const
{
	return !m_orphans.empty();
}

bool k8s_namespace_store::k8s_namespace::has_uid() const
{
	return m_uid != "";
}

void k8s_namespace_store::k8s_namespace::clear_orphans()
{
	LOG_DEBUG("k8s_namespace_store namespace %s clearing orphans", m_name.c_str());
	m_orphans.clear();
}

bool k8s_namespace_store::k8s_namespace::is_complete() const
{
	return has_uid();
}

void k8s_namespace_store::k8s_namespace::add_orphan(const std::string& kind, const std::string& id)
{
	auto ret = m_orphans.emplace(kind, id);

	if(ret.second == false)
	{
		LOG_DEBUG("k8s_namespace_store could not add orphan <%s,%s>",
				  kind.c_str(),
				  id.c_str());
	}
}

const std::set<k8s_namespace_store::orphan_uid_t>& k8s_namespace_store::k8s_namespace::get_orphans() const
{
	return m_orphans;
}

k8s_namespace_store::k8s_namespace_store()
{
}

k8s_namespace_store::~k8s_namespace_store() noexcept
{
}

void k8s_namespace_store::add_namespace(const std::string& ns_name, const std::string& ns_id)
{
	if(!has_namespace(ns_name))
	{
		LOG_DEBUG("k8s_namespace_store adding %s namespace %s",
				  ns_id.empty() ? "incomplete" : "complete",
				  ns_name.c_str());

		if(ns_id.empty())
		{
			m_namespaces.insert(std::make_pair(ns_name, k8s_namespace(ns_name)));
		}
		else
		{
			m_namespaces.insert(std::make_pair(ns_name, k8s_namespace(ns_name, ns_id)));
		}
	}
	else
	{
		LOG_DEBUG("k8s_namespace_store trying to re-add namespace %s which is already in the store", 
				  ns_name.c_str());
	}
}

void k8s_namespace_store::clear()
{
	m_namespaces.clear();
	m_child_to_namespace_uid.clear();
}

void k8s_namespace_store::add_child_to_namespace(const std::string &ns_name, const std::string &child_id)
{
	auto pos = m_namespaces.find(ns_name);

	if(pos == m_namespaces.end())
	{
		LOG_WARNING("k8s_namespace_store could not add %s to ns %s because ns is not in the store", child_id.c_str(), ns_name.c_str());
	}
	else
	{
		LOG_DEBUG("k8s_namespace_store add child %s to ns %s", child_id.c_str(), ns_name.c_str());
		m_child_to_namespace_uid[child_id] = pos->second.uid();
	}
}

std::string k8s_namespace_store::lookup_ns_by_object_uid(const std::string &child_id) const
{
	std::string ret;
	auto pos = m_child_to_namespace_uid.find(child_id);
	if(pos != m_child_to_namespace_uid.end())
	{
		ret = pos->second;
	}
	return ret;
}

void k8s_namespace_store::handle_event(const draiosproto::congroup_update_event &evt)
{
	auto& cg = evt.object();
	auto& kind = cg.uid().kind();

	if(kind == k8s_namespace_store::KIND_NAMESPACE
		|| object_kind_is_namespaced(kind))
	{
		switch(evt.type())
		{
			case draiosproto::ADDED:
				handle_add(cg);
				break;
			case draiosproto::REMOVED:
				handle_rm(cg);
				break;
			default:
				break;
		}
	}
}

// If cg is a namespace, and we already had stored its namespace name, then just add to it
// the namespace uid. Otherwise add to the store the namespace and its uid
// if cg is an object different from namespace and we have not seen its namespace yet,
// create the namespace and add the orphan to it.
// children ARE NOT added here
void k8s_namespace_store::handle_add(const draiosproto::container_group& cg)
{
	auto kind = cg.uid().kind();
	auto id = cg.uid().id();

	std::string ns_name;
	if(kind == KIND_NAMESPACE)
	{
		ns_name = cg.namespace_();

		ASSERT(!ns_name.empty());
		// check if we already have the namespace (it could be non ready with orphans)
		auto pos = m_namespaces.find(ns_name);
		if(pos != m_namespaces.end())
		{
			ASSERT(seen_namespace_object(ns_name) == false);
			ASSERT(pos->second.uid() == "");
			pos->second.set_uid(id);
			LOG_DEBUG("k8s_namespace_store namespace <%s,%s> is now complete. It has  %lu orphans",
				  kind.c_str(),
				  id.c_str(),
				  pos->second.get_orphans().size());
		}
		else
		{
			add_namespace(ns_name, id);
		}
	}
	else
	{
		ns_name = cg.namespace_();

		if(!ns_name.empty())
		{
			// If namespace does not exist create an unready one
			if(!has_namespace(ns_name))
			{
				add_namespace(ns_name);
			}

			if(!seen_namespace_object(ns_name))
			{
				try
				{
					add_orphan_to_namespace(ns_name, kind, id);
				}
				catch(const k8s_namespace_store_error& e)
				{
					LOG_WARNING("k8s_namespace_store Cannot add orphan <%s,%s> to namespace %s "
					            "because the namespace is complete",
							    kind.c_str(),
							    id.c_str(),
							    ns_name.c_str());
				}
			}
		}
		else
		{
			LOG_WARNING("k8s_namespace_store Container group <%s,%s> does not contain any \"namespace\" internal tag",
					    cg.uid().kind().c_str(), cg.uid().id().c_str());
		}
	}

}

void k8s_namespace_store::handle_rm(const draiosproto::container_group& cg)
{
	auto kind = cg.uid().kind();
	auto id = cg.uid().id();

	std::string ns_name;
	if(kind == KIND_NAMESPACE)
	{
		ns_name = cg.namespace_();

		auto pos = m_namespaces.find(ns_name);

		if(pos == m_namespaces.end())
		{
			LOG_DEBUG("k8s_namespace_store request to remove an unknown namespace: %s", ns_name.c_str());
		}
		else
		{
			m_namespaces.erase(pos);
		}
	}
	else
	{
		m_child_to_namespace_uid.erase(id);
	}
}

bool k8s_namespace_store::namespace_has_orphans(const std::string& ns_name) const
{
	bool ret = false;
	auto pos = m_namespaces.find(ns_name);
	if(pos == m_namespaces.end())
	{
		LOG_DEBUG("k8s_namespace_manager request for namespace %s orphans but ns is not in the store", ns_name.c_str());
	}
	else
	{
		ret = pos->second.has_orphans();
	}
	return ret;
}

bool k8s_namespace_store::seen_namespace_object(const std::string& ns_name) const
{
	bool ret = false;
	auto pos = m_namespaces.find(ns_name);
	if(pos != m_namespaces.end())
	{
		ret = !pos->second.uid().empty();
	}
	return ret;
}

k8s_namespace_store::ns_to_orphans_map_t k8s_namespace_store::get_all_orphans_of_complete_namespaces() const
{
	decltype(get_all_orphans_of_complete_namespaces()) ret;
	for(const auto& ns_pair : get_namespaces())
	{
		auto& ns = ns_pair.second;

		if(ns.has_orphans() && ns.is_complete())
		{
			std::vector<k8s_namespace_store::orphan_uid_t>& vec = ret[std::make_pair(ns.name(), ns.uid())];

			for(const auto& orphan : ns.get_orphans())
			{
				vec.emplace_back(orphan.first, orphan.second);
			}
		}
	}

	return ret;
}

void k8s_namespace_store::add_orphan_to_namespace(const std::string& ns_name, const std::string& kind, const std::string& id)
{
	auto pos = m_namespaces.find(ns_name);
	if(pos == m_namespaces.end())
	{
		LOG_WARNING("k8s_namespace_store request to add an orphan to a non stored namespace %s", ns_name.c_str());
	}
	else
	{
		if(seen_namespace_object(ns_name))
		{
			throw k8s_namespace_store_error("cannot add orphans to a complete namespace");
		}

		LOG_DEBUG("k8s_namespace_store adding orphan <%s,%s> to namespace %s",
				  kind.c_str(),
				  id.c_str(),
				  pos->first.c_str());
		pos->second.add_orphan(kind, id);
		LOG_DEBUG("k8s_namespace_store namespace %s has %lu orphans", ns_name.c_str(), pos->second.get_orphans().size());
	}
}

const std::map<std::string, k8s_namespace_store::k8s_namespace>& k8s_namespace_store::get_namespaces() const
{
	return m_namespaces;
}

void k8s_namespace_store::clear_namespace_orphans(const std::string& ns_name)
{
	auto pos = m_namespaces.find(ns_name);
	if(pos == m_namespaces.end())
	{
		LOG_DEBUG("k8s_namespace_store request to delete orphan for non stored namespace %s", ns_name.c_str());
	}
	else
	{
		pos->second.clear_orphans();
	}
}

bool k8s_namespace_store::has_namespace(const std::string& ns_name) const
{
	return m_namespaces.find(ns_name) != m_namespaces.end();
}

bool k8s_namespace_store::object_kind_is_namespaced(const std::string& kind)
{
	return kind != "container"
		&& kind != "host"
		&& kind != "k8s_node"
		&& kind != "k8s_namespace"
		&& kind != "k8s_persistentvolume";
}

const std::string k8s_namespace_store::KUBERNETES_NAMESPACE_NAME = "kubernetes.namespace.name";
const std::string k8s_namespace_store::KIND_NAMESPACE = "k8s_namespace";
const std::string k8s_namespace_store::NAMESPACE_TAG = "namespace";

