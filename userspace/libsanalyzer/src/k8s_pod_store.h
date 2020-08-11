#pragma once

#include <string>
#include <map>
#include <vector>
#include <gtest/gtest.h>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/mem_fun.hpp>
#include <boost/multi_index/member.hpp>

#include "draios.pb.h"
#include "k8s_object_store.h"

/*! This class caches pods, services and nodes to create
    parent - child links
*/
class k8s_pod_store : public k8s_object_store
{
public:
	/*!
	  An Utility class for storing pods
	 */
	class pod
	{
	public:
		/*
		  \param id The pod uuid
		  \param namespace Then namespace the pod belongs to
		  \param node_name The node the pod belongs to
		  \param labels The set of pod's labels
		  \param port_names The pod's port (name and number)
		 */
		pod(const uid_t& id, const std::string& ns, const std::string& node_name, label_set_t&& labels, port_names_t&& ports);
		pod(const pod&) = delete;
		pod(pod&&);
		~pod();

		/*
		  \return Get the pod's labels
		 */
		const label_set_t& labels() const;

		/*
		  \return The pod's ports
		 */
		const port_names_t& ports() const;

		/*
		  \return The pod's node
		 */
		const std::string& node() const;

		/*
		  \return The pod's namespace
		 */
		const std::string& namespace_() const;

		pod& operator=(const pod&) = delete;
	private:
		uid_t m_id;
		std::string m_namespace;
		label_set_t m_labels;
		port_names_t m_port_names;
		std::string m_node_name;
	};

	/*!
	  An utility class for storing services
	 */
	class service
	{
	public:
		/*!
		  ctor
		  \param uid The service's id
		  \param name The service name
		  \param ns The service's namespace
		  \param selectors The service's selectors
		 */
		service(const std::string& uid, const std::string& name, const std::string& ns, selector_set_t&& selectors);
		service(const service&) = delete;
		service(service&&);
		~service();

		/*!
		  Keep track of pods under this service.
		  The info will be used later to remove links
		  if this service will be deleted
		  \param uid The pod uid
		 */
		void add_matched_pod(const std::string& uid) const;

		/*!
		  Getter
		  \return The service's selector
		 */
		const selector_set_t& selectors() const;

		/*
		  Getter
		  \return The service's uid
		 */
		const std::string& uid() const;

		/*
		  Getter
		  \return The service's name
		*/
		const std::string& name() const;

		/*
		  Getter
		  \return The service's namespace
		*/
		const std::string& namespace_() const;

		/*
		  Getter
		  \return all the services under this service
		 */
		const std::set<std::string>& matched_pods() const;

		/*
		  Verifies if a pod is served by this service
		  \param pod The target pod
		 */
		bool serves_pod(const pod& pod) const;

	private:
		mutable std::set<std::string> m_matched_pod;
		std::string m_uid;
		std::string m_name;
		std::string m_namespace;
		selector_set_t m_selectors;
	};

	using pod_cache_t = std::map<uid_t, pod>;

	k8s_pod_store();
	~k8s_pod_store();

	/*!
	  Call this method when an ADD event arrives from cointerface.
	  It will insert in the interal caches pods, services and nodes
	  Does nothing for any other object type
	  \param key The key used to store the object into m_state
	  \param state The infrastructure state
	 */
	void handle_add(const state_key_t& key, state_t& state) override;

	/*!
	  Call this method when an UPDATE event arrives from cointerface
	  It will remove and reinsert pods, services and nodes in the
	  internal cache
	  \param key The key used to store the object into m_state
	  \param state The infrastructure state
	 */
	void handle_update(const state_key_t& key, state_t& state) override;

	/*!
	  Call this method when a DELETE methods arrives from cointerface
	  It will delete pods, services and nodes from the interal caches
	  \param key The key used to store the object into m_state
	  \param state The infrastructure state
	 */
	void handle_delete(const state_key_t& cg, state_t& state) override;

	/*
	  Clear all the internal caches
	 */
	void clear() override;

	/*
	 * \return The overall size of all the internal caches
	 */
	uint64_t size() const override;

	/*
	 * Print some useful information (mainly meant for logging)
	 */
	void print_store_status() const override;

private:
	FRIEND_TEST(k8s_pod_store_test, search_pod_service_parent);
	FRIEND_TEST(k8s_pod_store_test, get_labels_from_cg);
	FRIEND_TEST(k8s_pod_store_test, resolve_ports);
	pod_cache_t m_pods;
	node_map_t m_nodes;

	// Multi index map for storing services
	// We index by service id and by service name
	struct index_id
	{
	};

	struct index_name
	{
	};
 	typedef boost::multi_index::multi_index_container<
		service,
		boost::multi_index::indexed_by<
			boost::multi_index::ordered_non_unique<boost::multi_index::tag<struct index_name>, boost::multi_index::const_mem_fun<service, const std::string&, &service::name>>,
			boost::multi_index::ordered_unique<boost::multi_index::tag<struct index_id>, boost::multi_index::const_mem_fun<service, const std::string&, &service::uid>>> >
	service_map_t;

	service_map_t m_services;

	// Store statefulsets waiting for their parent service.
	// We use a multimap whose key is the pair service's namespace and name. The value is the waiting
	// statefulset id
	std::multimap<std::pair<std::string, std::string>, std::string> m_statefulsets_waiting_for_service;

	void add_pod(const uid_t& pod_uid, const std::string& ns, const std::string& node_name, label_set_t&& labels, port_names_t&& ports);
	void add_service(const std::string& service_uid, const std::string& service_name, const std::string& ns, selector_set_t&& selectors);

	// serch in the service set for a service whose selectors match the pod's label
	std::string search_for_pod_parent_service(const std::string& pod_uid);

	// search in pods set for all the target service's children
	std::vector<std::string> search_for_service_children_pods(const std::string& service_uid, const std::string& service_name);

	std::string get_service_name(const draiosproto::container_group& cg);

	label_set_t get_labels_from_cg(const draiosproto::container_group& cg) const;
	port_names_t get_ports_from_cg(const draiosproto::container_group& cg) const;

	void resolve_ports(draiosproto::container_group& cg, const std::vector<std::string>& matches) const;

	void handle_add_pod(draiosproto::container_group& cg, state_t& state);
	void handle_add_service(draiosproto::container_group& cg, state_t& state);
	void handle_add_node(draiosproto::container_group& cg, state_t& state);
	void handle_add_statefulset(draiosproto::container_group& cg, state_t& state);
	void remove_service_from_pod(const std::string& pod_id, const std::string& service_id, state_t& state);
};
