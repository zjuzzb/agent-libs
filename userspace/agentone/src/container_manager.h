#pragma once

#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <atomic>

namespace agentone
{
// foredeclarations
template<typename container_container>
class container_serializer;

class container
{
public:
	container(const std::string& id,
	          const std::string& name,
	          const std::string& image,
	          const std::map<std::string, std::string>& labels);

	/**
	 * accesses to these fields are NOT locked, and therefore we should not
	 * add set methods unless we protect them
	 */
	const std::string& get_id() const ;
	const std::string& get_name() const;
	const std::string& get_image() const;
	const std::map<std::string, std::string>& get_labels() const;

	/**
	 * add and remove refs from this container. should ONLY be used by container_manager
	 * See comment below on why the regular ref in shared_ptr is not sufficient.
	 */
	void ref();
	void deref();
	uint32_t get_ref() const;

private:
	const std::string m_id;
	const std::string m_name;
	const std::string m_image;
	const std::map<std::string, std::string> m_labels;

	// Containers are usually passed around via a shared_ptr, so why do we need our
	// own ref? Well, there is a difference between the necessity of the in memory
	// representation of a container existing, and the necessity of it existing in
	// the container manager. When this counter hits 0, the container_manager's
	// ref on this container can be removed. When the shared_ptr ref hits 0,
	// the object can be freed.
	std::atomic<uint32_t> m_existence_ref;
};

class container_manager
{
public:
	container_manager();

	/**
	 * Builds a container to be managed by the container manager
	 *
	 * If a container with this ID currently exists, this is a no-op (but for the ref
	 * described below), regardless if the other metadata is equal.
	 *
	 * Regardless of whether or not the new container was built, the caller, once
	 * they have called build_container MUST eventually call remove container in order for
	 * the container to be destroyed.
	 */
	void build_container(const std::string& id,
	                     const std::string& name,
	                     const std::string& image,
	                     const std::map<std::string, std::string>& labels);

	/**
	 * removes our reference to this container. This may lead to destruction of the
	 * container. The only thing this function guarantees will happen is that the
	 * caller acknowledges this container no longer exists. This does not mean the
	 * container is removed from the container manager or deleted. Other operations which MAY
	 * occur include
	 *
	 * 1) removal from the container manager, if all clients who had "built" this container
	 *    have now removed it
	 * 2) destruction of the container object, if (1) occurs, and this is the last 
	 *    reference anywhere to the in memory object
	 */
	void remove_container(const std::string& id);

	/**
	 * returns a copy of the list of containers. This represents a point in time
	 * snapshot, and therefore the actual data may be different.
	 *
	 * Further, there is no guarantee the actual container process the objects
	 * in the list represent continue to exist.
	 *
	 * As this creates a copy of the list, performance implications should be considered,
	 * and this function should in general not be used.
	 */
	std::map<std::string, std::shared_ptr<container>> get_container_list() const;

	/**
	 * returns the container represented by the id, or a nullptr if it doesn't exist.
	 *
	 * Note: even if the container object exists, the process backing it may no longer
	 * exist (as the pointer returned here could be the last reference to it!)
	 */
	const std::shared_ptr<container> get_container(const std::string& id) const;

private:
	mutable std::mutex m_container_list_lock;  // Lock protects the containers by connection queue

	// It is guaranteed by the list lock that iff an container is in this list,
	// that container also has a reference to the connection.
	std::map<std::string, std::shared_ptr<container>> m_containers;
};

/**
 * a serializer for protobufs.
 *
 * The container_container is whatever struct that the serializer needs. It doesn't
 * have to implement anything in particular.
 */
template<typename container_container>
class container_serializer
{
public:
	void serialize(const container_manager& cm, container_container& message);
};

}  // namespace agentone
