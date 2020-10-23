#pragma once
#include <string>
#include <map>
#include <memory>

#include "draios.pb.h"

/*!
  A pure interface every cache has to implement
 */
class k8s_object_store
{
public:
	using state_key_t = std::pair<std::string, std::string>;
	using state_t = std::map<std::pair<std::string, std::string>, std::shared_ptr<draiosproto::container_group>>;
	using kind_and_name_t = std::pair<std::string, std::string>;
	using uid_t = std::string;
	using label_set_t = std::map<std::string, std::string>;
	using port_names_t = std::map<std::string /* port name */, /* port number */ uint32_t>;
	using selector_set_t = label_set_t;
	using service_cache_t = std::map<uid_t, selector_set_t>;
	using node_map_t = std::map<std::string, std::string>;


	static const std::string DEPLOYMENT_NAME_TAG;
	static const std::string REPLICASET_NAME_TAG;
	static const std::string REPLICATION_CONTROLLER_NAME_TAG;
	static const std::string DEPLOYMENT_KIND;
	static const std::string REPLICASET_KIND;
	static const std::string HPA_KIND;
	static const std::string REPLICATION_CONTROLLER_KIND;
	static const std::string TARGET_KIND_TAG;
	static const std::string TARGET_NAME_TAG;
	static const std::string SERVICE_KIND;
	static const std::string POD_KIND;
	static const std::string NODE_KIND;
	static const std::map<std::string, std::string> M_K8S_TO_SYSDIG_KIND;


	/*!
	  Every implemementation must define the behaviour when a ADD event arrives
	  \param key The key used to store the object into the infrastructure state (kind and name)
	  \param state The infrastructure state
	 */
	virtual void handle_add(const state_key_t& key, state_t& state) = 0;

	/*!
	  Every implemementation must define the behaviour when a UPDATE event arrives
	  \param key The key used to store the object into the infrastructure state (kind and name)
	  \param state The infrastructure state
	 */
	virtual void handle_update(const state_key_t& key, state_t& state) = 0;

	/*!
	  Every implemementation must define the behaviour when a DELETE event arrives
	  \param key The key used to store the object into the infrastructure state (kind and name)
	  \param state The infrastructure state
	 */
	virtual void handle_delete(const state_key_t& key, state_t& state) = 0;

	/*!
	  Every implemementation must clear all the internal caches
	 */
	virtual void clear() = 0;

	/*!
	  Every implemementation must return the sum of all the interal caches
	 */
	virtual uint64_t size() const = 0;

	/*!
	  Every implementation must log some useful informarmation about the internal caches
	 */
	virtual void print_store_status() const = 0;

protected:

	static std::pair<bool, state_t::iterator> has_key(const state_key_t& key, state_t& state);
	static kind_and_name_t get_cg_kind_and_name(const draiosproto::container_group& cg);

	// This function is ment to be used for setting parents or children.
	// It checks if the links is already in place and in this case emit a warning message
	// avoiding to set duplicated elements in the repeated field
	void set_link_or_warn(google::protobuf::RepeatedPtrField<draiosproto::congroup_uid>& rf, const state_key_t& new_link) const;

private:
	bool repeated_field_has_link(const google::protobuf::RepeatedPtrField<draiosproto::congroup_uid>& rf, const state_key_t& new_link) const;
};
