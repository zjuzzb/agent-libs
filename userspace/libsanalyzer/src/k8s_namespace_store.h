#include <string>
#include <vector>
#include <map>
#include <set>
#include <utility>

#include <gtest/gtest_prod.h>

#include "draios.pb.h"


//! A store that helps to associate a kubernetes object with its namespace
class k8s_namespace_store
{
public:
	using uid_t = std::pair<std::string, std::string>;
	using orphan_uid_t = std::pair<std::string, std::string>;

	k8s_namespace_store();
	~k8s_namespace_store() noexcept;

	/*!
	  Add a namespace to the store
	  \param ns_name The namespace's name
	  \param ns_id The namespace id. If empty it means that
	               the namespace add event has not yet arrived and its id is unknown.
                       The namespace is then in incomplete state.
	 */
	void add_namespace(const std::string& ns_name, const std::string& ns_id = "");

	/*
	  Check if namespace is in the store and then add a child
	  \param ns_name The namespace name we want to add a child to
	  \param child_id the id of the object we want to add as a child
	 */
	void add_child_to_namespace(const std::string& ns_name, const std::string& child_id);

	/*
	  Clear the object structures: namespaces, children, orphans
	 */
	void clear();

	/*
	  Look in the store for an object id. Return the namespace's id it belongs to.
	  return an empty string if the object is not in the store
	  \param child_id The object's id we want to find the namespace of.
	  \return The parent's namespace id
	 */
	std::string lookup_ns_by_object_uid(const std::string& child_id) const;

	/*
	  This method is called whenever an event arrives from cointerface.
	  The event is then dispatched on event type specific handlers
	  \param evt The event (e.g. congroup and event type ADD, UPDATE, etc...)
	 */
	void handle_event(const draiosproto::congroup_update_event& evt);

	/*
	  Check if a (incomplete) namespace has orphans
	  A namespace has orphans as long as it does not have an id
	  (i.e. the namespace ADD event has not yet arrived). Once the its
	  ADD event arrives (along with its id), the namespace become "complete"
	  and all its orphans are turned to children.

	  \param ns_name The name of the namespace we want to check for orphans
	  \return True if it has orphans. False otherwise
	 */
	bool namespace_has_orphans(const std::string& ns_name) const;

	/*
	  This method should be called when we get an ADD object event, whose namespace
	  id is still unknown (i.e. the namespace ADD event has not yet arrived)
	  The method throw an k8s_namespace_store_error if the namespace is complete
	  (in this case add_child_to_namespace should be called)

	  \param ns_name The name of the namespace we want to add the orphan to
	  \param kind The orphan's kind (e.g. k8s_deployment, k8s_pod, etc...)
	  \param id The orphan id
	 */
	void add_orphan_to_namespace(const std::string& ns_name, const std::string& kind, const std::string& id);

	/*
	  Delete all the namespace ophans
	  \param ns_name The namespace's name we want to delete the orphans to
	 */
	void clear_namespace_orphans(const std::string& ns_name);

	/*
	  Check if a namespace is in the store
	  \param ns_name The namespace's name we want to check
	  \return true if namespace is in the store, false otherwise
	 */
	bool has_namespace(const std::string& ns_name) const;

	/*
	  Check if a namespace is complete. A namespace is said to be
	  complete if it has a name and an id as well (which means
	  that its ADD event has arrived)
	  \param ns_name The name of the namespace we want to check
	  \return True if namespace is complete false otherwise (included if namespace
	          is not in the store)
	 */
	bool seen_namespace_object(const std::string& ns_name) const;

	using ns_to_orphans_map_t = std::map<uid_t, std::vector<orphan_uid_t>>;

	/*
	  Looks the store for all namespaces that have orphans and are complete.
	  This is used to turn orphans into children. Orphans must be deleted
	  calling clear_namespace_orphans
	 */
	ns_to_orphans_map_t get_all_orphans_of_complete_namespaces() const;

	/*
	  An utility to check if an object is hierarchically under a namespace
	  (e.g. Nodes, Hosts are not)
	  \param kind The target's object kind
	  \return True if the object is hierarchically under namespace. False otherwise
	 */
	static bool object_kind_is_namespaced(const std::string& kind);

	static const std::string KUBERNETES_NAMESPACE_NAME;
	static const std::string KIND_NAMESPACE;
	static const std::string NAMESPACE_TAG;

private:
	FRIEND_TEST(infrastructure_state_test, connect_to_namespace);
	FRIEND_TEST(infrastructure_state_test, k8s_namespace_store_test);

	//! An helper class that store namespace's info:
	// name, uid, orphans
	class k8s_namespace
	{
	public:
		k8s_namespace(k8s_namespace&&);
		~k8s_namespace() noexcept;

		/*
		  \return The namespace name
		 */
		std::string name() const;

		/*
		  \return The namespace uid
		 */
		std::string uid() const;

		/*
		  \return True if namespace has orphans. False otherwise
		 */
		bool has_orphans() const;

		/*
		  \return True if namespace has an uid (i.e. the ADD event carrying the uid has already arrived).
		          False otherwise
		 */
		bool has_uid() const;

		/*
		  Add an orphan to the namespace. The method does not check if namespace is
		  complete (in which case a children should be added instead of an orphan).
		  So before calling it, the method namespace_is_complete should be called

		  \param kind The kind of the orphan we want to add
		  \param id   The id of the orphan we want to add
		 */
		void add_orphan(const std::string& kind, const std::string& id);

		/*
		  This method is supposed to be called whenever we receive
		  the ADD event carrying the namespace uid. In this case, the namespace
		  can already be in the store because we already received an object living
		  in the namespace (a pod, a deployment, etc...)

		  \param id The namespace id
		 */
		void set_uid(const std::string& id);

		/*
		  Remove all the namespace's orphans
		 */
		void clear_orphans();

		/*
		  \return The namespace's orphans
		 */
		const std::set<orphan_uid_t>& get_orphans() const;

		/*
		  Check if namespace has name and uid as well.
		  In other words, check that we already got the namespace ADD event.
		 */
		bool is_complete() const;

	private:
		friend class k8s_namespace_store;
		explicit k8s_namespace(const std::string& name);
		explicit k8s_namespace(const std::string& name, const std::string& id);

		std::string m_name;
		std::string m_uid;
		std::set<orphan_uid_t> m_orphans;
	};


	/*
	  This method handle the ADD event.
	  It is responsible of adding incomplete namespaces,
	  complete namespaces, adding orphans to namespaces,
	  turning incomplete namespaces to complete.

	  \param cg Container group coming from cointerface
	 */
	void handle_add(const draiosproto::container_group& cg);

	/*
	  This method handle remove events. Depending on the object kind,
	  it deletes namespaces from the store, or remove a child from a namespace.
	 */
	void handle_rm(const draiosproto::container_group& cg);

	/*
	  Get all the namespaces in the store
	  \return A map with the namespace's name as key and the namespace struct as value
	 */
	const std::map<std::string, k8s_namespace>& get_namespaces() const;


	std::map<std::string /*name*/, k8s_namespace> m_namespaces;
	std::map<std::string /*child_id*/,std::string /*namespace_name*/> m_child_to_namespace_uid;
};
