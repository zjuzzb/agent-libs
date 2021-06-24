#pragma once

#include "analyzer_utils.h"
#include "connectinfo.h"
#include "infrastructure_state.h"
#include "type_config.h"

#include <draios.pb.h>
#include <secure.pb.h>
#include <sinsp.h>

#include "secure_helper.h"

typedef google::protobuf::RepeatedPtrField<draiosproto::container_group> container_groups;

typedef struct k8s_communication k8s_communication;

// Pod Owner
typedef secure::K8SPodOwner k8s_pod_owner;
typedef std::unordered_map<std::string, unique_ptr<k8s_pod_owner>> k8s_pod_owner_map;

// Cron Jobs
typedef secure::K8SCronJob k8s_cronjob;
typedef std::unordered_map<std::string, unique_ptr<k8s_cronjob>> k8s_cronjob_map;

typedef std::unordered_map<std::string, std::unique_ptr<std::set<std::string>>> k8s_cronjob_jobs_map;

// Metadata
typedef secure::K8SObjectMeta k8s_object_meta;
typedef secure::K8SObjectMeta k8s_metadata;

// Endpoints
typedef secure::K8SEndpoint k8s_endpoint;
typedef std::unordered_map<std::string, std::unique_ptr<k8s_endpoint>> k8s_endpoint_map;
// Namespaces
typedef secure::K8SNamespace k8s_namespace;
typedef std::unordered_map<std::string, std::unique_ptr<k8s_namespace>> k8s_namespace_map;
// Services
typedef secure::K8SService k8s_service;
typedef std::unordered_map<std::string, std::unique_ptr<k8s_service>> k8s_service_map;

void convert_label_selector(secure::K8SLabelSelector *secure_label_selector,
			    draiosproto::K8SLabelSelector label_selector);

// k8s_communication is a wrapper on secure::K8SCommunication class
// and provides methods to manage the communication enrichment process.
// A communication is essentially composed of:
//   1. ipv4/tcp 5-tuple
//   2. client owner/command
//   3. server owner/command
struct k8s_communication
{
	k8s_communication(
		const ipv4tuple& tuple,
		bool is_client,
		bool is_server):
		m_client_resolved(false),
		m_has_client_comm(false),
		m_is_client(is_client),
		m_server_resolved(false),
		m_has_server_comm(false),
		m_is_server(is_server),
		m_is_host_activity(false)
	{
		// Key is a 5-tuple, with sport set to 0. It will be
		// later have the hash value of the client comm.
		m_key.m_fields.m_sip = tuple.m_fields.m_sip;
		m_key.m_fields.m_dip = tuple.m_fields.m_dip;
		m_key.m_fields.m_sport = 0; // key sport default to 0,

		// add the sport to the set
		m_sport_set.insert(tuple.m_fields.m_sport);
		
		m_key.m_fields.m_dport = tuple.m_fields.m_dport;
		m_key.m_fields.m_l4proto = tuple.m_fields.m_l4proto;

		// K8SCommunication Protobuf data
		m_communication.set_client_ipv4(ntohl(tuple.m_fields.m_sip));
		m_communication.set_server_ipv4(ntohl(tuple.m_fields.m_dip));
		m_communication.set_server_port(tuple.m_fields.m_dport);
		m_communication.set_l4_protocol(secure_helper::scap_l4_to_ip_l4(tuple.m_fields.m_l4proto));
	}

	const ipv4tuple& get_key() const
	{
		return m_key;
	}

	bool has_sport(uint16_t sport) const
	{
		return m_sport_set.find(sport) != m_sport_set.end();
	}

	void add_sport(uint16_t sport)
	{
		m_sport_set.insert(sport);
	}

	// client owner
	void add_owner_client(string uid)
	{
		m_client_resolved = true;
		m_communication.set_client_owner_uid(uid);
	}

	string get_uid_client() const
	{
		return m_communication.client_owner_uid();
	}

	bool is_client_resolved() const
	{
		return m_client_resolved;
	}

	// client command
	void add_comm_client(string comm)
	{
		m_has_client_comm = true;
		m_communication.set_client_comm(comm);
	}

	string get_comm_client() const
	{
		return m_communication.client_comm();
	}

	bool has_comm_client() const
	{
		return m_has_client_comm;
	}

	bool is_server_resolved() const
	{
		return m_server_resolved;
	}

	// server owner
	void add_owner_server(string uid)
	{
		m_server_resolved = true;
		m_communication.set_server_owner_uid(uid);
	}

	string get_uid_server() const
	{
		return m_communication.server_owner_uid();
	}

	// server command
	void add_comm_server(string comm)
	{
		m_has_server_comm = true;
		m_communication.set_server_comm(comm);
	}

	bool has_comm_server() const
	{
		return m_has_server_comm;
	}

	string get_comm_server() const
	{
		return m_communication.server_comm();
	}

	bool is_client() const
	{
		return m_is_client;
	}

	bool is_client_only() const
	{
		return m_is_client & !m_is_server;
	}

	bool is_server() const
	{
		return m_is_server;
	}

	bool is_server_only() const
	{
		return !m_is_client & m_is_server;
	}

	bool is_client_and_server() const
	{
		return m_is_client & m_is_server;
	}

	bool is_client_and_server_resolved() const
	{
		return m_client_resolved && m_server_resolved;
	}

	void set_is_self_local(bool is_self_local)
	{
		m_communication.set_is_self_local(is_self_local);
	}

	bool is_self_local() const
	{
		return m_communication.is_self_local();
	}

	bool is_host_activity() const
	{
		return m_is_host_activity;
	}

	void set_is_host_activity(bool is_host_activity)
	{
		m_is_host_activity = is_host_activity;
	}

	void serialize_protobuf(secure::K8SCommunication *c);

	std::set<uint16_t> m_sport_set;

private:
	bool add_owner(const draiosproto::container_group& cg, secure::K8SPodOwner& owner);

	// key (ipv4 5-tuple with a twist. Client port set to either 0
	// or hash(client_comm))
	ipv4tuple m_key;

	// client
	bool        m_client_resolved;
	bool        m_has_client_comm;
	bool        m_is_client;
	// server
	bool        m_server_resolved;
	bool        m_has_server_comm;
	bool        m_is_server;
	// protobuf
	secure::K8SCommunication m_communication;
	bool m_is_host_activity;
};

typedef std::unordered_map<ipv4tuple, std::unique_ptr<k8s_communication>, ip4t_hash, ip4t_cmp> k8s_communication_map;

// Cluster communication holds information regarding the relevant
// metadata of a communication summary. It consists of:
//   1. Communications: ingresses/egress
//   2. Pod Owners
//   3. Endpoints/Services/Namespaces
struct k8s_cluster_communication
{
	static type_config<bool> c_network_topology_skip_host_activity;

	k8s_communication_map* get_ingresses()
	{
		return &m_ingresses;
	}

	k8s_communication_map* get_egresses()
	{
		return &m_egresses;
	}

	void clear()
	{
		m_ingresses.clear();
		m_egresses.clear();
		m_owners.clear();
		m_cronjobs.clear();
		m_cronjobs_jobs.clear();

		m_endpoints.clear();
		m_services.clear();
		m_namespaces.clear();
	}

	// returns if there's at least one connection
	bool has_data() const
	{
		return !m_ingresses.empty()
			|| !m_egresses.empty();
	}

	// returns true if there is at least one ingress communication
	// fully resolved (resolved)
	bool has_communication_resolved_ingress(ipv4tuple tuple)
	{
		return has_communication_resolved(m_ingresses, tuple);
	}

	bool insert_or_update_communication_ingress(ipv4tuple tuple,
						    const k8s_communication& k8s_comm)
	{
		if (has_communication_resolved_ingress(tuple))
		{
			return false;
		}

		return insert_or_update_communication(m_ingresses, tuple, k8s_comm);
	}

	// returns true if there is at least one egress communication
	// fully resolved (resolved)
	bool has_communication_resolved_egress(ipv4tuple tuple)
	{
		return has_communication_resolved(m_egresses, tuple);
	}

	bool insert_or_update_communication_egress(ipv4tuple tuple,
						   const k8s_communication& k8s_comm)
	{
		if (has_communication_resolved_egress(tuple))
		{
			return false;
		}

		return insert_or_update_communication(m_egresses, tuple, k8s_comm);
	}

	bool add_owner(const k8s_pod_owner &owner)
	{
		const auto& key = owner.metadata().uid();
		bool is_new_entry = false;

		const auto& it = m_owners.find(key);
		if (it == m_owners.end())
		{
			m_owners[key] = make_unique<k8s_pod_owner>(owner);
			is_new_entry = true;
		}

		return is_new_entry;
	}

        void add_job_to_cronjob(const string &cronjob_uid,
				const string &job_uid);

	bool add_endpoint(std::string &key, k8s_endpoint& e);
	bool add_service(std::string &key, k8s_service& s);
	bool add_namespace(std::string &key, k8s_namespace& n);
	bool add_cronjob(std::string &key, k8s_cronjob& cj);

	void serialize_protobuf(secure::K8SClusterCommunication*& cluster);
    void serialize_protobuf_v2(secure::K8SClusterCommunication*& cluster);

private:
	k8s_communication_map m_ingresses;
	k8s_communication_map m_egresses;
	k8s_pod_owner_map     m_owners;
	k8s_cronjob_map       m_cronjobs;
	k8s_cronjob_jobs_map  m_cronjobs_jobs;
	k8s_endpoint_map      m_endpoints;
	k8s_service_map       m_services;
	k8s_namespace_map     m_namespaces;

	bool has_communication_resolved(k8s_communication_map& cset,
					ipv4tuple tuple)
	{
		auto sport = tuple.m_fields.m_sport;
		tuple.m_fields.m_sport = 0;

		const auto& it = cset.find(tuple);
		if (it == cset.end())
		{
			return false;
		}

		const auto& c = it->second.get();

		// check if communication has source port
		if (!c->has_sport(sport))
		{
			return false;
		}

		// check if evaluated communication has more resolved
		// components
		if (!c->is_client_resolved())
		{
			return false;
		}
		if (!c->is_server_resolved())
		{
			return false;
		}

		return true;
	}

	bool insert_or_update_communication(k8s_communication_map& cmap,
					    ipv4tuple tuple,
					    const k8s_communication& k8s_comm)
	{
		auto sport = tuple.m_fields.m_sport;
		tuple.m_fields.m_sport = 0;

		bool is_new_entry = false;

		const auto& it = cmap.find(tuple);
		if (it == cmap.end())
		{
			cmap[tuple] = make_unique<k8s_communication>(k8s_comm);
			is_new_entry = true;
		}
		else // Entry already exists, but might not have fully
		     // enriched data. Try to fill out missing gaps
		{
			auto c = it->second.get();

			// Update sport_set
			if(!c->has_sport(sport))
			{
				c->add_sport(sport);
			}

			// Client
			if (!c->has_comm_client() &&
			    k8s_comm.has_comm_client())
			{
				c->add_comm_client(k8s_comm.get_comm_client());
			}
			if (!c->is_client_resolved() &&
			    k8s_comm.is_client_resolved())
			{
				c->add_owner_client(k8s_comm.get_uid_client());
			}

			// Server
			if (!c->has_comm_server() &&
			    k8s_comm.has_comm_server())
			{
				c->add_comm_server(k8s_comm.get_comm_server());
			}
			if (!c->is_server_resolved() &&
			    k8s_comm.is_server_resolved())
			{
				c->add_owner_server(k8s_comm.get_uid_server());
			}
		}

		return is_new_entry;
	}

	bool validate_self_local_egresses(ipv4tuple tuple) const;
	bool validate_self_local(k8s_communication *k8s_comm) const;

	void serialize_communications(const k8s_communication_map& cmap,
				      ::google::protobuf::RepeatedPtrField<secure::K8SCommunication> *p);

	void serialize_pod_owners(const k8s_pod_owner_map& k8s_owners,
				  ::google::protobuf::RepeatedPtrField<secure::K8SPodOwner> *p);

	void serialize_cronjob_jobs();


	template<typename M, typename T>
		bool add_map_entry_unique(M& cmap, const std::string& key, T& value);

	template<typename M, typename T>
		void serialize_map_to_protobuf(const M& cmap, ::google::protobuf::RepeatedPtrField<T> *p);
};
