#pragma once

#include "agentino_connection.h"
#include "connection_manager.h"
#include "container_manager.h"
#include "security_result_handler.h"
#include "thread_pool.h"
#include "running_state_runnable.h"

#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <thread>
#include <string>

/**
 * Agentino management infrastructure
 *
 * agentino: represents a single agentino
 * agentino_manager: as it sounds. Manages the life cycle of individual agentinos
 *
 * In general, most clients will only need to ask for perhaps the agentino list, or
 * metadata from a particular agentino. Currently the creation and deletion of agentinos
 * is all managed via connections. As it stands now, there is no way to create or destroy
 * an agentino outside of having a connection to it, so as far as the AM is concerned,
 * there is a 1-1 relationship. As such, things such as reconnecting to an existing
 * agentino do not exist and functions supporting that (get_extant_agentino(metadata,
 * add_connection/metadata)
 * are left unimplemented.
 */
// Foredeclarations
namespace draiosproto
{
class policies_v2;
class policy_events;
}  // namespace draiosproto

// actual code
namespace agentone
{
enum agentino_metadata_property
{
	CONTAINER_ID = 0,
	CONTAINER_NAME = 1,
	CONTAINER_IMAGE = 2,
};

class agentino_manager;

class agentino
{
public:
	using ptr = std::shared_ptr<agentino>;

private:  // constants
	const std::string unfound_metadata_property_value = "";

public:  // ctor/dtor
	/**
	 * builds the proper implementation of an agentino based on the known metadata
	 */
	static ptr build_agentino(agentino_manager* manager,
	                          connection::ptr connection_in,
	                          std::map<agentino_metadata_property, std::string> fixed_metadata,
	                          std::map<std::string, std::string> arbitrary_metadata);

	// create agentino with or without a connection
	agentino(agentino_manager* manager);
	agentino(agentino_manager* manager,
	         connection::ptr connection_in,
	         std::map<agentino_metadata_property, std::string> fixed_metadata,
	         std::map<std::string, std::string> arbitrary_metadata);

public:

	/**
	 * Get a unique identifier for this agentino.
	 */
	virtual std::string get_id() const;

	/**
	 * stores the metadata value for the given property. If that property had been
	 * previously written, it is overwritten
	 */
	void add_metadata_property(agentino_metadata_property property, const std::string& value);
	void add_metadata_property(const std::string& property, const std::string& value);

	/**
	 * returns the metadata value of the specificied property, or an empty string
	 * if no such property is stored
	 */
	const std::string& get_metadata_property(agentino_metadata_property property) const;
	const std::string& get_metadata_property(const std::string& property) const;

	/**
	 * adds the container to the to the list of containers represented by the agentino
	 *
	 * returns false if the container already existed
	 */
	bool add_container(std::shared_ptr<container> container_in);
	void remove_container(std::shared_ptr<container> container_in);

	/**
	 * acquires the list of containers. Makes a copy of the list
	 */
	std::map<std::string, std::shared_ptr<container>> get_container_list() const;

	/**
	 * assigns a connection info to a currently existing agentino for which
	 * we may not have current connection info
	 */
	void add_connection_info(connection::ptr connection_in);

	/**
	 * gets the connection associated with this agentino, otherwise nullptr
	 */
	const connection::ptr get_connection_info() const;

	/**
	 * removes the connection info from this agentino
	 */
	void remove_connection_info();

	/**
	 * sends a protobuf to this agentino
	 *
	 * Fire-and-forget. No return value. Best of luck.
	 */
	template<typename PROTOBUF>
	void send(draiosproto::message_type type, PROTOBUF buffer)
	{
		if (m_connection)
		{
			(void)m_connection->send_message(type, buffer);
		}
	}

protected:
	// The following lock protects BOTH the container and metadata structures.
	// It is not expected to be contended enough that those structures need finer
	// grained locking
	mutable std::mutex m_metadata_lock;
	agentino_manager* m_manager;

	std::map<std::string, std::shared_ptr<container>> m_containers;

private:
	// We have two metadata maps. One contains data of types we know (because, for instance,
	// we have to stuff them in specific fields in a protobuf). This can be keyed by an
	// enum since the keys are therefore limited by the fields in the protobuf. The
	// Second is for anything else, and thus is keyed by an arbitrary string.
	std::map<agentino_metadata_property, std::string> m_fixed_metadata;
	std::map<std::string, std::string> m_arbitrary_metadata;

	/**
	 * manages data about the incoming connection to this agentino
	 *
	 * may not exist at all times if the connection is destroyed but
	 * we are still maintaining metadata about this agentino. In v1, however,
	 * the connection and agentino are effectively 1-1, as we do not
	 * allow an agentino w/o a connection.
	 */
	connection::ptr m_connection;
};

/**
 * an agentino representing an ECS task. Assumes CONTAINER_ID is one of the metadata fields.
 * If other container metadata fields (name, image) are not provided, it is not an error
 * and they are set as empty strings
 */
class ecs_agentino : public agentino
{
public:
	ecs_agentino(agentino_manager* manager,
	             connection::ptr connection_in,
	             std::map<agentino_metadata_property, std::string> fixed_metadata,
	             std::map<std::string, std::string> arbitrary_metadata);
	~ecs_agentino();
};

/**
 * Locking semantics:
 *
 * There is no implied locking order between the two locks in this class (policies and
 * agentino list). As such, it should be avoided that they are taken at the same time. If
 * that becomes cumbersome, we can consider a lcking order in the future.
 *
 * There IS however, an implied locking order between this class and others. It ges
 * (from most broadly scoped lock to most fine grained)
 * - agentino_manager::agentino list lock
 * - agentino:: any locks
 * - container_manager:: any locks
 *
 *   Therefore, say, the container manager should never call into the agentino manager
 *   while loding a lock, or the agentino.
 */
class agentino_manager : public connection_manager::message_handler
{
public:
	static uint64_t get_current_ts_ns()
	{
		struct timeval tv;
		gettimeofday(&tv, NULL);

		return tv.tv_sec * (uint64_t)1000000000 + tv.tv_usec * 1000;
	}

public:
	agentino_manager(security_result_handler& events_handler,
	                 container_manager& container_manager_in,
	                 const std::string& machine_id,
	                 const std::string& customer_id);
	~agentino_manager();

	// Make sure we don't accidentally copy the AM
	agentino_manager(const agentino_manager&) = delete;
	agentino_manager& operator=(const agentino_manager&) = delete;

	/**
	 * Listen for incoming agentino connections on the given port.
	 */
	void listen(uint16_t port);

	/**
	 * Tear down the listen thread.
	 */
	void stop_listening();

	/**
	 * Process the incoming handshake protobuf and provide a response.
	 *
	 * If function returns true, incoming handshake is valid and the response
	 * parameter is populated.
	 *
	 * If function returns false, incoming handshake is invalid and the
	 * response parameter is undefined.
	 */
	bool handle_agentino_handshake(const draiosproto::agentino_handshake&,
	                               draiosproto::agentino_handshake_response&);

	/**
	 * When the listening socket receives a new connection.
	 */
	void new_agentino_connection(connection::ptr connection);

	/**
	 * A connection has dropped and should be removed from tracking.
	 */
	void delete_agentino_connection(connection::ptr connection);

	/**
	 * returns a copy of the list of agentinos. This represents a point in time
	 * snapshot, and therefore the actual data may be different.
	 *
	 * Further, there is no guarantee the actual agentino process the objects
	 * in the list represent continue to exist.
	 *
	 * As this creates a copy of the list, performance implications should be considered,
	 * and this function should in general not be used.
	 */
	std::set<agentino::ptr> get_agentino_list() const;

	/**
	 * returns the agentino represented by the id, or a nullptr if it doesn't exist.
	 *
	 * Note: even if the agentino object exists, the process backing it may no longer
	 * exist (as the pointer returned here could be the last reference to it!)
	 */
	const agentino::ptr get_agentino(connection::ptr connection_in) const;

	/**
	 * Get the number of agentino connections currently being managed by this manager.
	 */
	uint32_t get_num_connections() const;

public:  // message_handler
	bool handle_message(draiosproto::message_type type,
	                    const uint8_t* buffer,
	                    size_t buffer_size) override;

private:  // functions
	// we assume all these are called with the lock held
	agentino::ptr find_extant_agentino_not_threadsafe(
	    const std::map<agentino_metadata_property, std::string>& metadata) const;
	agentino::ptr find_extant_agentino_not_threadsafe(connection::ptr connection_in) const;
	void agentino_connection_lost(agentino::ptr agentino_in);

	/**
	 * Polls all active agentino connections for incoming data and handles them.
	 *
	 * We need to scale pretty dramatically regarding number of agentinos
	 * supported, and this method is how we do that. All the agentino sockets are
	 * passed into a list and polled at once.
	 *
	 * Building the list each time is probably pretty inefficient. We have all the
	 * mechanisms in place for the agentino manager to maintain the list rather
	 * than rebuilding it each time. That's a TODO.
	 */
	void build_agentino_poll_list(std::list<cm_socket::poll_sock>&) const;

	/**
	 * Runs the network loop for the agentino manager / agentinos
	 */
	void poll_and_dispatch(std::chrono::milliseconds timeout);

	// the run function for our thread
	void run();

	// sends our cached policies to all the agentinos. NOT guaranteed thread safe and therefore
	// should ONLY ever be invoked from the agentino_manager thread, otherwise there is
	// possibility of race between two sending policies to the same agent, which
	// could be out of order (thus pushing an older policies message)
	void propagate_policies();

public:
	/**
	 * Parses the handshake protobuf into our usable in-memory structs
	 *
	 * @param handshake_data the protobuf which contains the metadata
	 * @param fixed_metadata the output param containing certain fixed fields
	 * @param arbitrary_metadata the output param containing all other arbitrary metadata
	 */
	static void build_metadata(const draiosproto::agentino_handshake& handshake_data,
	                           std::map<agentino_metadata_property, std::string>& fixed_metadata,
	                           std::map<std::string, std::string>& arbitrary_metadata);

public:
	container_manager& m_container_manager;

private:
	volatile bool m_shutdown;
	security_result_handler& m_events_handler;
	mutable std::mutex m_agentino_list_lock;  // Lock protects the agentinos by connection queue

	// It is guaranteed by the list lock that iff an agentino is in this list,
	// that agentino also has a reference to the connection.
	std::map<connection::ptr, agentino::ptr> m_agentinos_by_connection;

	std::set<std::shared_ptr<agentino>> m_agentinos;

	// This list solves the problem of what happens if policies are updated AFTER
	// the handshake is responded to, but BEFORE we are on the agentino list. This guarantees
	// the agentino_manager thread will send the policies at least once. Could also
	// be solved by some sort of policy versioning or lock-ordering between policies
	// and agentino list lock, but this was sufficient. Downside is we might double send
	// a policy, but that is live-with-able.
	std::list<std::shared_ptr<agentino>> m_new_agentinos;

	std::mutex m_policies_lock;  // lock protects the cached policies and updated flag
	draiosproto::policies_v2 m_cached_policies;
	bool m_policies_updated;  // indicates that the policies have been updated, but not yet
	                          // propagated to the agentinos

	// Cached IDs for populating protobufs
	const std::string m_machine_id;
	const std::string m_customer_id;

	// The pool is used to manage per-agentino socket events. The thread is
	// for the server socket and other one-off stuff the manager needs to do
	// COuld probably be combined at some point.
	thread_pool m_pool;
	std::thread m_thread;

	friend class test_helper;
};

}  // namespace agentone
