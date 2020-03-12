#pragma once
#include <map>
#include <string>
#include <gtest/gtest.h>

#include "k8s_object_store.h"
#include "draios.pb.h"


/*!
  This class' objective is to help to create relationships between HPA and target controllers.
  We cannot get this relationship using the ownerReference field in cointerface, because HPA does not own a controller.
  Moreover, k8s API returns the HPA target as a pair kind-name. And we need to remap it in a UUID
 */
class k8s_hpa_store : public k8s_object_store
{
public:

	k8s_hpa_store();
	~k8s_hpa_store() noexcept;

	// Implementing k8s_object_store

	/*
	  Handle an add event from cointerface.
	  Store kind, name and uid of HPAs and potential HPA targets to reconstruct parent-child relationships
	  \param key The key used to store the object into m_state
	  \param state The infrastructure state
	 */
	void handle_add(const k8s_object_store::state_key_t& key, k8s_object_store::state_t& state) override;

	/*
	  Delete and re-add the object from internal caches
	  \param key The key used to store the object into the infrastructure state (kind and name)
	  \param state The infrastructure state
	 */
	void handle_update(const k8s_object_store::state_key_t& key, k8s_object_store::state_t& state) override;

	/*
	  Delete the object from the internal cache
	  \param key The key used to store the object into the infrastructure state (kind and name)
	  \param state The infrastructure state
	 */
	void handle_delete(const k8s_object_store::state_key_t& key, k8s_object_store::state_t& state) override;

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
	FRIEND_TEST(k8s_hpa_store_test, connect_hpa_to_target);
	FRIEND_TEST(k8s_hpa_store_test, get_hpa_target_kind_and_name);
	void insert_potential_target(const std::string& kind, const std::string& name, const std::string& uid);
	bool can_be_hpa_target(const draiosproto::container_group& cg) const;
	void connect_hpa_to_target(const state_key_t& key, state_t& state);

	void insert_object_if_eligible(const draiosproto::container_group& cg);
	uid_t lookup_target(const std::string& kind, const std::string& name);
	void set_hpa_waiting_for_target(const uid_t& hpa_uid, kind_and_name_t&& target);
	bool has_hpa_waiting_for_target() const;
	uid_t lookup_for_waiting_hpa(const draiosproto::container_group& cg);

	static std::pair<std::string, std::string> get_hpa_target_kind_and_name(const draiosproto::container_group& cg);

	std::map<kind_and_name_t, uid_t> m_targets;
	std::map<kind_and_name_t, uid_t> m_hpa_waiting_for_target;
};
