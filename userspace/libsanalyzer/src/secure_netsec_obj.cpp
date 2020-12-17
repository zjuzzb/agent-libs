#include "common_logger.h"
#include "secure_netsec_obj.h"

COMMON_LOGGER();

type_config<bool> k8s_cluster_communication::c_network_topology_skip_host_activity(true,
    "Skip network communication where at least one of the endpoint IP belongs to a host",
    "network_topology", "skip_host_activity");

bool k8s_cluster_communication::add_endpoint(std::string& key, k8s_endpoint& e)
{
	return add_map_entry_unique<k8s_endpoint_map, k8s_endpoint>(m_endpoints, key, e);
}

bool k8s_cluster_communication::add_service(std::string& key, k8s_service& s)
{
	return add_map_entry_unique<k8s_service_map, k8s_service>(m_services, key, s);
}

bool k8s_cluster_communication::add_namespace(std::string& key, k8s_namespace& n)
{
	return add_map_entry_unique<k8s_namespace_map, k8s_namespace>(m_namespaces, key, n);
}

bool k8s_cluster_communication::add_cronjob(std::string& key, k8s_cronjob& cj)
{
	return add_map_entry_unique<k8s_cronjob_map, k8s_cronjob>(m_cronjobs, key, cj);
}

void k8s_cluster_communication::add_job_to_cronjob(const string &cronjob_uid,
			const string &job_uid)
{
	auto it = m_cronjobs_jobs.find(cronjob_uid);
	if (it == m_cronjobs_jobs.end())
	{
		m_cronjobs_jobs[cronjob_uid] = make_unique<std::set<std::string>>();
	}

	m_cronjobs_jobs[cronjob_uid]->insert(job_uid);
}


void k8s_cluster_communication::serialize_communications(
	const k8s_communication_map& cmap,
	::google::protobuf::RepeatedPtrField<secure::K8SCommunication> *p)
{
	for (const auto& it : cmap)
	{
		// Marking connection as self_local is done during the
		// serialization phase, as it requires looking at
		// matching entries from ingress-to-egress
		// communication.
		if (validate_self_local(it.second.get()))
		{
			it.second->set_is_self_local(true);
		}

		// If specified by the config, skip all host
		// activities
		if (c_network_topology_skip_host_activity.get_value() &&
		    it.second->is_host_activity())
		{
			continue;
		}

		auto a = p->Add();
		it.second.get()->serialize_protobuf(a);
	}
}

// Add an entry to a map of unique_ptrs. Return true if a new entry
// has been inserted, false otheriwise.
template<typename M, typename T>
bool k8s_cluster_communication::add_map_entry_unique(
	M& cmap,
	const std::string& key,
	T& value)
{
	bool is_new_entry = false;
	const auto& it = cmap.find(key);
	if (it == cmap.end())
	{
		cmap[key] = make_unique<T>(value);
		is_new_entry = true;
	}

	return is_new_entry;
}

// Serialize a map, by hard copying protobuf entries
template<typename M, typename T>
void k8s_cluster_communication::serialize_map_to_protobuf(
	const M& cmap,
	::google::protobuf::RepeatedPtrField<T> *p)
{
	for (const auto& it : cmap)
	{
		auto a = p->Add();
		a->CopyFrom(*it.second.get());
	}
}

void k8s_cluster_communication::serialize_cronjob_jobs()
{
	for (const auto &it : m_cronjobs_jobs)
	{
		auto cjit = m_cronjobs.find(it.first);

		if(cjit != m_cronjobs.end())
		{
			cjit->second->mutable_job_uids()->Clear();

			for (const auto &jit : *(it.second))
			{
				cjit->second->add_job_uids(jit);
			}
		}
	}

	// Now that we've added any jobs to the set of cronjobs,
	// remove any cronjobs that have no job uids.
	auto it = m_cronjobs.begin();

	while (it != m_cronjobs.end())
	{
		if(it->second->job_uids().size() == 0)
		{
			it = m_cronjobs.erase(it);
		}
		else
		{
			it++;
		}
	}
}

void k8s_cluster_communication::serialize_protobuf(
	secure::K8SClusterCommunication*& cluster)
{
	// It's important that egresses are serialized first, so they
	// can get the is_self_local label assigned. That allows
	// matching ingresses to get the label when they are
	// serialized in the second pass.
	serialize_communications(m_egresses, cluster->mutable_egresses());
	serialize_communications(m_ingresses, cluster->mutable_ingresses());

	serialize_map_to_protobuf<k8s_pod_owner_map, k8s_pod_owner>
		(m_owners, cluster->mutable_pod_owners());

	serialize_map_to_protobuf<k8s_endpoint_map, k8s_endpoint>
		(m_endpoints, cluster->mutable_endpoints());
	serialize_map_to_protobuf<k8s_namespace_map, k8s_namespace>
		(m_namespaces, cluster->mutable_namespaces());
	serialize_map_to_protobuf<k8s_service_map, k8s_service>
		(m_services, cluster->mutable_services());

	serialize_cronjob_jobs();
	serialize_map_to_protobuf<k8s_cronjob_map, k8s_cronjob>
		(m_cronjobs, cluster->mutable_cronjobs());
}

bool k8s_cluster_communication::validate_self_local_egresses(ipv4tuple tuple) const
{
	const auto &it_tcp = m_egresses.find(tuple);
	if (it_tcp != m_egresses.end())
	{
		return it_tcp->second->is_self_local();
	}

	return false;
}

// Mark self-local connections (self pod-to-pod only), esclude
// pod-svc-pod. The condition to be a self-local connection.
bool k8s_cluster_communication::validate_self_local(k8s_communication *k8s_comm) const
{
	bool is_self_local = false;
	auto tuple = k8s_comm->get_key();

	// only consider the case where we have matching
	// source/destination IPs
	if (tuple.m_fields.m_sip == tuple.m_fields.m_dip)
	{
		// client only side connection: trivial
		if (k8s_comm->is_client_only() ||
		    k8s_comm->is_client_and_server())
		{
			is_self_local = true;
		}
		// server only or client & server side connection;
		// here we have two scenarios: (A) pod-pod or (B)
		// pod-svc-pod. We want to mark `is_self_local' only
		// on the latter case. To do so, we need to check if
		// we have a correspondent matching connection in the
		// egress maps, indicating that we have observed a
		// client only side connection
		else if (k8s_comm->is_server_only())
		{
			if (validate_self_local_egresses(tuple))
			{
				is_self_local = true;
			}
		}
	}

	return is_self_local;
}

void k8s_communication::serialize_protobuf(secure::K8SCommunication *c)
{
	c->CopyFrom(m_communication);
}
