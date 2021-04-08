#include "agentino.pb.h"
#include "agentino_manager.h"
#include "agentino_message.h"
#include "protocol.h"
#include "thread_pool.h"

#include <cassert>

using namespace agentone;

namespace
{
type_config<uint16_t> c_agentino_port(6667,
                                      "Port to listen for agentino connections on.",
                                      "agentino_port");
type_config<bool> c_agentino_ssl(true, "Use SSL for agentino connections?", "agentino_ssl");
type_config<uint16_t>::ptr c_tp_size =
    type_config_builder<uint16_t>(2,
                                  "Number of threads in the manager's thread pool.",
                                  "agentino_tp_threads")
        .min(1)
        .hidden()
        .build();
type_config<uint64_t> c_agentino_manager_socket_poll_timeout_ms(
    300,
    "the mount of time the socket poll waits before returning",
    "agentino_manager",
    "socket_poll_timeout_ms");

COMMON_LOGGER();

// the cast should happen in connection, and then we can just point to the member
// methods directly. SMAGENT-2858
bool handshake_callback_helper(agentone::agentino_manager* am,
                               void* ctx,
                               const draiosproto::agentino_handshake& hs,
                               draiosproto::agentino_handshake_response& hs_resp)
{
	return am->handle_agentino_handshake(hs, hs_resp);
}

void connect_callback_helper(agentone::agentino_manager* am,
                             std::shared_ptr<connection> conn,
                             void* ctx)
{
	am->new_agentino_connection(conn);
}

void disconnect_callback_helper(agentone::agentino_manager* am,
                                std::shared_ptr<connection> conn,
                                void* ctx)
{
	am->delete_agentino_connection(conn);
}

}  // namespace

/**
 * Thread pool work item for completing agentino connection.
 *
 * Completing the connection includes receiving the handshake and sending the
 * handshake response.
 */
class listen_work_item : public tp_work_item
{
public:
	listen_work_item(connection::ptr& connp) : m_conn_ctx(connp) {}

	~listen_work_item() {}

	virtual void handle_work() override
	{
		connection::set_connected_ref(m_conn_ctx);
		if (!m_conn_ctx->start(nullptr))
		{
			LOG_ERROR("Failed to connect to new agentino");
		}
	}

private:
	connection::ptr m_conn_ctx;
};

class agentino_message_work_item : public tp_work_item
{
public:
	agentino_message_work_item(agentino_manager& am, raw_message& msg)
	    : m_agentino_ctx(am),
	      m_msg(msg)
	{
	}

	virtual void handle_work() override
	{
		draiosproto::message_type type =
		    static_cast<draiosproto::message_type>(m_msg.hdr.hdr.messagetype);

		LOG_INFO("Handling agentino message of type %d", (int)type);
		// Dispatch the message
		(void)m_agentino_ctx.handle_message(type, m_msg.bytes, m_msg.payload_length());
	}

private:
	agentino_manager& m_agentino_ctx;
	raw_message m_msg;
};

agentino::ptr agentino::build_agentino(
    agentino_manager* manager,
    connection::ptr connection_in,
    std::map<agentino_metadata_property, std::string> fixed_metadata,
    std::map<std::string, std::string> arbitrary_metadata)
{
	if (fixed_metadata.find(CONTAINER_ID) != fixed_metadata.end())
	{
		return std::make_shared<ecs_agentino>(manager,
		                                      std::move(connection_in),
		                                      std::move(fixed_metadata),
		                                      std::move(arbitrary_metadata));
	}

	return std::make_shared<agentino>(manager,
	                                  std::move(connection_in),
	                                  std::move(fixed_metadata),
	                                  std::move(arbitrary_metadata));
}

agentino::agentino(agentone::agentino_manager* manager) : agentino(manager, nullptr, {}, {}) {}

agentino::agentino(agentone::agentino_manager* manager,
                   connection::ptr connection_in,
                   std::map<agentino_metadata_property, std::string> fixed_metadata,
                   std::map<std::string, std::string> arbitrary_metadata)
    : m_manager(manager),
      m_fixed_metadata(fixed_metadata),
      m_arbitrary_metadata(arbitrary_metadata),
      m_connection(connection_in)
{
}

std::string agentino::get_id() const
{
	if (m_fixed_metadata.find(CONTAINER_ID) != m_fixed_metadata.end())
	{
		return m_fixed_metadata.at(
		    CONTAINER_ID);  // Container ID is a globally unique identifier for the container
	}

	// Container name is not guaranteed to be unique, but maybe good as a fallback?
	if (m_fixed_metadata.find(CONTAINER_NAME) != m_fixed_metadata.end())
	{
		return "(non_unique) " + m_fixed_metadata.at(CONTAINER_NAME);
	}

	return "<unknown>";
}

std::string agentino::get_name() const
{
	if (m_fixed_metadata.find(CONTAINER_NAME) != m_fixed_metadata.end())
	{
		return m_fixed_metadata.at(
		    CONTAINER_NAME);  // Container NAME is not guaranteed to be unique
	}

	return "<unknown>";
}

void agentino::add_metadata_property(agentino_metadata_property property, const std::string& value)
{
	std::lock_guard<std::mutex> lock(m_metadata_lock);
	m_fixed_metadata[property] = value;
}

void agentino::add_metadata_property(const std::string& property, const std::string& value)
{
	std::lock_guard<std::mutex> lock(m_metadata_lock);
	m_arbitrary_metadata[property] = value;
}

const std::string& agentino::get_metadata_property(agentino_metadata_property property) const
{
	std::lock_guard<std::mutex> lock(m_metadata_lock);
	auto value = m_fixed_metadata.find(property);
	if (value == m_fixed_metadata.end())
	{
		return unfound_metadata_property_value;
	}
	return value->second;
}

const std::string& agentino::get_metadata_property(const std::string& property) const
{
	std::lock_guard<std::mutex> lock(m_metadata_lock);
	auto value = m_arbitrary_metadata.find(property);
	if (value == m_arbitrary_metadata.end())
	{
		return unfound_metadata_property_value;
	}
	return value->second;
}

bool agentino::add_container(std::shared_ptr<container> container_in)
{
	std::lock_guard<std::mutex> lock(m_metadata_lock);

	if (m_containers.find(container_in->get_id()) != m_containers.end())
	{
		return false;
	}

	m_containers.insert(
	    std::pair<std::string, std::shared_ptr<container>>(container_in->get_id(), container_in));

	return true;
}

void agentino::remove_container(std::shared_ptr<container> container_in)
{
	std::lock_guard<std::mutex> lock(m_metadata_lock);

	if (m_containers.find(container_in->get_id()) != m_containers.end())
	{
		m_containers.erase(m_containers.find(container_in->get_id()));
	}
}

std::map<std::string, std::shared_ptr<container>> agentino::get_container_list() const
{
	std::lock_guard<std::mutex> lock(m_metadata_lock);
	return m_containers;
}

const connection::ptr agentino::get_connection_info() const
{
	std::lock_guard<std::mutex> lock(m_metadata_lock);
	return m_connection;
}

void agentino::add_connection_info(connection::ptr connection_in)
{
	std::lock_guard<std::mutex> lock(m_metadata_lock);
	m_connection = connection_in;
}

void agentino::remove_connection_info()
{
	std::lock_guard<std::mutex> lock(m_metadata_lock);
	m_connection = nullptr;
}

ecs_agentino::ecs_agentino(agentone::agentino_manager* manager,
                           connection::ptr connection_in,
                           std::map<agentino_metadata_property, std::string> fixed_metadata,
                           std::map<std::string, std::string> arbitrary_metadata)
    : agentino(manager, connection_in, fixed_metadata, arbitrary_metadata)
{
	// We now have the agentino, and know that there must be a container backing this
	// agentino. So create it now.
	manager->m_container_manager.build_container(fixed_metadata[CONTAINER_ID],
	                                             fixed_metadata[CONTAINER_NAME],
	                                             fixed_metadata[CONTAINER_IMAGE],
	                                             arbitrary_metadata);
	add_container(manager->m_container_manager.get_container(fixed_metadata[CONTAINER_ID]));
}

// Note that despite this call USUALLY occurring when the connection is destroyed, and thus
// under the agentino list lock, that doesn't HAVE to be the case, if someone else
// had a pointer to the agentino.
//
// At such a time, however, a NEW connection could be formed for what amounts to the same
// agentino. As far as the agentino manager is concerned, the agentino is already dead,
// so it creates a new agentino. At that time, the new agentino will invoke "build_container"
// on a container with the same ID. This will cause the container to be reffed, and
// then when the defunct version of the agentino invokes "remove container" here,
// it will not actually be removed.
ecs_agentino::~ecs_agentino()
{
	for (auto& i : m_containers)
	{
		m_manager->m_container_manager.remove_container(i.first);
	}
}

agentino_manager::agentino_manager(security_result_handler& events_handler,
                                   container_manager& container_manager_in,
                                   const std::string& machine_id,
                                   const std::string& customer_id)
    : m_container_manager(container_manager_in),
      m_shutdown(false),
      m_events_handler(events_handler),
      m_policies_updated(false),
      m_machine_id(machine_id),
      m_customer_id(customer_id),
      m_pool(c_tp_size->get_value()),
      m_thread(&agentino_manager::run, this)
{
	listen(c_agentino_port.get_value());
}

agentino_manager::~agentino_manager()
{
	if (!m_shutdown)
	{
		m_shutdown = true;
		m_thread.join();
		stop_listening();
	}
}

void agentino_manager::build_metadata(
    const draiosproto::agentino_handshake& handshake_data,
    std::map<agentino_metadata_property, std::string>& fixed_metadata,
    std::map<std::string, std::string>& arbitrary_metadata)
{
	fixed_metadata.insert(std::pair<agentino_metadata_property, std::string>(
	    CONTAINER_ID,
	    handshake_data.metadata().container_id()));
	fixed_metadata.insert(std::pair<agentino_metadata_property, std::string>(
	    CONTAINER_NAME,
	    handshake_data.metadata().container_name()));
	fixed_metadata.insert(std::pair<agentino_metadata_property, std::string>(
	    CONTAINER_IMAGE,
	    handshake_data.metadata().container_image()));

	for (auto& pair : handshake_data.metadata().other_metadata())
	{
		arbitrary_metadata.insert(pair);
	}
}

void agentino_manager::new_agentino_connection(connection::ptr connection_in)
{
	std::lock_guard<std::mutex> lock(m_agentino_list_lock);
	std::map<agentino_metadata_property, std::string> fixed_metadata;

	draiosproto::agentino_handshake handshake_data;
	bool ret = connection_in->get_handshake_data(handshake_data);
	if (!ret)
	{
		// This message will always print name=<unknown> id=<unknown>, because it
		// is the handshake data that populates the metadata for the agentinos.
		LOG_WARNING(
		    "Attempting to process new connection with no handshake data, bailing for container "
		    "name=%s id=%s",
		    fixed_metadata[CONTAINER_NAME].c_str(),
		    connection_in->get_id().c_str());
		return;
	}

	std::map<std::string, std::string> arbitrary_metadata;
	agentino_manager::build_metadata(handshake_data, fixed_metadata, arbitrary_metadata);

	// See if we already have an object for this agentino. This is not supported in
	// V1. If the object already exists (with a connection), we will create a
	// second connection and agentino, and the first one will roll off when the connection
	// is destroyed. Container manager correctly handles this. When SMAGENT-2860 is
	// implemented, we will look up the agentino by metadata to see if one already exists
	agentino::ptr extant_agentino = nullptr;
	if (extant_agentino == nullptr)
	{
		LOG_INFO("Building new agentino from container name=%s id=%s",
		         fixed_metadata[CONTAINER_NAME].c_str(),
		         fixed_metadata[CONTAINER_ID].c_str());
		extant_agentino = build_agentino(connection_in,
		                                 std::move(fixed_metadata),
		                                 std::move(arbitrary_metadata));
		m_agentinos.insert(extant_agentino);
		m_agentinos_by_connection.emplace(connection_in, extant_agentino);
	}

	connection_in->set_id(extant_agentino->get_id());
	connection_in->set_name(extant_agentino->get_name());
	// to be picked up by the agentino_manager thread to ensure we have most recent policies
	m_new_agentinos.push_back(extant_agentino);
}

void agentino_manager::delete_agentino_connection(connection::ptr connection_in)
{
	std::lock_guard<std::mutex> lock(m_agentino_list_lock);
	if (!connection_in)
	{
		// Though we might get two callbacks, both of them should be providing a valid
		// pointer
		LOG_ERROR("Attempting to remove agentino based on null connection info!");
		return;
	}

	agentino::ptr extant_agentino = find_extant_agentino_not_threadsafe(connection_in);

	if (extant_agentino == nullptr)
	{
		// There are two paths to remove an agentino:
		// 1. An I/O call from agentino_manager fails
		// 2. We get a disconnect callback from the connection object
		// It's very possible for us to get a remove from both these paths,
		// which is not an error. It's just life with networking code.
		LOG_DEBUG("Attempting to remove unknown agentino connection from container %s",
		          connection_in->get_id().c_str());
		return;
	}
	LOG_INFO("Removing agentino from container name=%s id=%s",
	         connection_in->get_name().c_str(),
	         connection_in->get_id().c_str());
	extant_agentino->remove_connection_info();

	// We do not support leaving agentinos around after the connection died yet
	m_agentinos.erase(m_agentinos.find(extant_agentino));
	m_agentinos_by_connection.erase(m_agentinos_by_connection.find(connection_in));
}

agentino::ptr agentino_manager::find_extant_agentino_not_threadsafe(
    const std::map<agentino_metadata_property, std::string>& metadata) const
{
	// currently do not support reconnecting via metadata
	LOG_ERROR("This function is not implemented and should not be called.");
	return nullptr;
}

agentino::ptr agentino_manager::find_extant_agentino_not_threadsafe(
    connection::ptr connection_in) const
{
	auto extant_agentino = m_agentinos_by_connection.find(connection_in);
	if (extant_agentino == m_agentinos_by_connection.end())
	{
		return nullptr;
	}

	return extant_agentino->second;
}

void agentino_manager::listen(uint16_t port)
{
	auto new_conn_cb = [this](cm_socket* sock, void* ctx) {
		// Get the agentino manager from the context
		auto* am = (agentino_manager*)ctx;

		// Translate the socket into a connection object
		connection::ptr connp = std::make_shared<connection>(sock,
		                                                     am,
		                                                     handshake_callback_helper,
		                                                     connect_callback_helper,
		                                                     disconnect_callback_helper);

		// Complete the connection on a thread pool thread
		m_pool.submit_work(new listen_work_item(connp));
	};

	auto conn_error_cb = [port](cm_socket::error_type et, int error, void* ctx) {
		// Get the agentino manager from the context
		auto* am = (agentino_manager*)ctx;

		LOG_ERROR("Listening for agentino connections failed: %d, %d", (int)et, (int)error);

		// We're going to try again now
		am->listen(port);
	};

	bool ssl = c_agentino_ssl.get_value();
	bool ret = cm_socket::listen({port, ssl}, new_conn_cb, conn_error_cb, this);
	if (!ret)
	{
		LOG_ERROR("Could not listen for agentino connections");
	}
}

void agentino_manager::stop_listening()
{
	cm_socket::stop_listening(true);
}

// /////////////
// Functions for polling the sockets of connected agentinos

void agentino_manager::build_agentino_poll_list(std::list<cm_socket::poll_sock>& out) const
{
	out.clear();
	std::lock_guard<std::mutex> lock(m_agentino_list_lock);

	for (auto& agentino : m_agentinos)
	{
		// We have to bump the refcount on the shared pointer to make sure the
		// connection object doesn't vanish out from under us.
		auto connection = agentino->get_connection_info();
		if (connection)
		{
			auto socket = connection->get_socket();
			// Skip if this is a nullptr
			if (socket)
			{
				connection::ptr* cpp = new connection::ptr(agentino->get_connection_info());
				out.emplace_back(socket, cpp);
			}
		}
	}
}

void agentino_manager::poll_and_dispatch(std::chrono::milliseconds timeout)
{
	std::list<cm_socket::poll_sock> sock_list;
	std::list<cm_socket::poll_sock> ready_list;

	build_agentino_poll_list(sock_list);

	if (sock_list.empty())
	{
		// The run loop is relying on this function to sleep in order to not
		// busy wait. In the case where there are no agentinos connected, we
		// will sleep for the entire timeout value.
		// Note that this will not impact our ability to receive new agentino
		// connections, as that occurs on the listen thread. So by sleeping
		// in the zero-connected-agentinos case we are not jeopardizing our
		// ability to respond to an incoming connection.
		std::this_thread::sleep_for(timeout);
		return;
	}

	bool ret = cm_socket::poll(sock_list, ready_list, timeout);

	if (!ret)
	{
		LOG_ERROR("Communications error: Could not poll for agentino messages");
		goto cleanup;
	}

	if (ready_list.size() > 0)
	{
		LOG_DEBUG("Poll returned a list of length %d", (int)ready_list.size());
	}

	for (auto& psock : ready_list)
	{
		connection::ptr* cptr = (connection::ptr*)psock.ctx;

		raw_message msg;

		// Read the message
		connection::result res = (*cptr)->read_message(msg);
		if (res == connection::SUCCESS)
		{
			draiosproto::message_type type =
			    static_cast<draiosproto::message_type>(msg.hdr.hdr.messagetype);
			if (type == draiosproto::message_type::AGENTINO_HEARTBEAT)
			{
				// Heartbeat message, nothing to do here
				LOG_DEBUG("Received heartbeat from agentino container name=%s id=%s",
				          (*cptr)->get_name().c_str(),
				          (*cptr)->get_id().c_str());
			}
			else
			{
				LOG_INFO(
				    "Read message of type %d and length %u from agentino container name=%s id=%s",
				    (int)type,
				    msg.payload_length(),
				    (*cptr)->get_name().c_str(),
				    (*cptr)->get_id().c_str());

				// Submit work queue item to deserialize and dispatch
				m_pool.submit_work(new agentino_message_work_item(*this, msg));
			}
		}
		else
		{
			LOG_WARNING(
			    "Error reading message from agentino"
			    "(probably agentino disconnected) container name=%s id=%s",
			    (*cptr)->get_name().c_str(),
			    (*cptr)->get_id().c_str());
			// Propagate the disconnect to the connection object
			(*cptr)->disconnect();
		}
	}

cleanup:

	// Now clean up the connection info pointers allocated at the start
	// (It's possible that this will be the final deref on this pointer and
	// will trigger the deletion of the connection object.)
	for (auto& psock : sock_list)
	{
		//
		// We are deleting a shared pointer that looks very wrong. It's not, however.
		//
		// the sock list context, for portability reasons takes a void* as its context.
		// As the connection itself is automatically managed, we need a ref on it at all
		// times. During the time it exists on the sock list, it may be the only ref.
		//
		// So the item we must put on the list is a shared pointer. As it's not an intrinsic
		// list and a void*, it must be allocated/freed manually. Other ways to deal with
		// this might be
		// - creating a wrapper for the list that deals with smart and regular pointers properly
		// - reffing the connection somewhere else
		// - Making the list intrinsically deal with connections instead of void*s
		//
		// The corresponding allocation is in build_agentino_poll_list
		std::shared_ptr<connection>* cptr = (connection::ptr*)psock.ctx;
		delete cptr;
	}
}

// End poll functions
// //////////////////////

std::set<agentino::ptr> agentino_manager::get_agentino_list() const
{
	std::lock_guard<std::mutex> lock(m_agentino_list_lock);
	return m_agentinos;
}

const agentino::ptr agentino_manager::get_agentino(connection::ptr connection_in) const
{
	std::lock_guard<std::mutex> lock(m_agentino_list_lock);
	return find_extant_agentino_not_threadsafe(connection_in);
}

uint32_t agentino_manager::get_num_connections() const
{
	std::lock_guard<std::mutex> lock(m_agentino_list_lock);
	return m_agentinos_by_connection.size();
}

draiosproto::policies_v2 agentino_manager::get_cached_policies() const
{
	std::lock_guard<std::mutex> lock(m_policies_lock);
	return m_cached_policies;
}

bool agentino_manager::handle_message(draiosproto::message_type type,
                                      const uint8_t* buffer,
                                      size_t buffer_size)
{
	LOG_DEBUG("Handling buffer of type %d and size %d", (int)type, (int)buffer_size);
	if (type == draiosproto::message_type::POLICIES_V2)
	{
		std::lock_guard<std::mutex> lock(m_policies_lock);
		try
		{
			dragent_protocol::buffer_to_protobuf(buffer, buffer_size, &m_cached_policies);
		}
		catch (dragent_protocol::protocol_error& ex)
		{
			LOG_ERROR("Protocol error while parsing policies message: %s", ex.what());
			return false;
		}

		m_policies_updated = true;
		return true;
	}
	else if (type == draiosproto::message_type::POLICY_EVENTS)
	{
		draiosproto::policy_events events;
		try
		{
			dragent_protocol::buffer_to_protobuf(buffer, buffer_size, &events);
		}
		catch (dragent_protocol::protocol_error& ex)
		{
			LOG_ERROR("Protocol error while parsing events message: %s", ex.what());
			return false;
		}

		uint64_t time_ns = get_current_ts_ns();
		// Need to set machine ID / customer ID to match agentone, as that's
		// what backend expects
		events.set_machine_id(m_machine_id);
		events.set_customer_id(m_customer_id);
		m_events_handler.security_mgr_policy_events_ready(time_ns, &events);
		return true;
	}
	else
	{
		LOG_ERROR("Agentino manager received unexpected message of type %d. Ignoring", type);
		return false;
	}
}

void agentino_manager::propagate_policies()
{
	// We make some copies of stuff to ensure we don't have to hold both the list lock
	// and the policies lock at the same time (which would cause some annoyances).
	//
	// So we cache the new agentinos, whether the policies have been updated, and
	// the policies themselves, and then send them to the appropriate agentinos.
	m_agentino_list_lock.lock();
	std::list<std::shared_ptr<agentino>> new_agentinos = m_new_agentinos;
	m_new_agentinos.clear();
	m_agentino_list_lock.unlock();

	m_policies_lock.lock();
	draiosproto::policies_v2 policies;
	bool made_policy_copy = false;  // to double check we never try to send policies we didn't load
	bool policies_updated = m_policies_updated;
	m_policies_updated = false;
	if (policies_updated || new_agentinos.size() != 0)
	{
		// Only make this copy if we actually will need it
		policies = m_cached_policies;
		made_policy_copy = true;
	}
	m_policies_lock.unlock();

	if (policies_updated)
	{
		if (!made_policy_copy)
		{
			LOG_ERROR("Sending bogus policies");
			assert(made_policy_copy);
		}
		std::lock_guard<std::mutex> lock(m_agentino_list_lock);
		for (auto& i : m_agentinos)
		{
			i->send_policies(policies);
		}
	}
	else
	{
		for (auto& i : new_agentinos)
		{
			if (!made_policy_copy)
			{
				LOG_ERROR("Sending bogus policies");
				assert(made_policy_copy);
			}
			i->send_policies(policies);
		}
	}
}

bool agentino_manager::handle_agentino_handshake(const draiosproto::agentino_handshake& hs_proto,
                                                 draiosproto::agentino_handshake_response& hs_resp)
{
	bool is_valid = false;
	// Validate the input proto
	uint64_t ts_in = hs_proto.timestamp_ns();
	if (ts_in > 0)
	{
		is_valid = true;
	}

	/// Validation happens here, but won't be any validation in v1
	// SMAGENT-2861
	if (!is_valid)
	{
		LOG_ERROR("Invalid handshake protobuf from agentino");
		return false;
	}

	// Populate the output proto
	hs_resp.set_timestamp_ns(get_current_ts_ns());
	m_policies_lock.lock();
	hs_resp.mutable_policies()->CopyFrom(m_cached_policies);
	m_policies_lock.unlock();

	return true;
}

void agentino_manager::run()
{
	while (!m_shutdown)
	{
		// Note: poll requires constant calls, and sleeps for 300ms before timing out.
		// So we'll check the policies propagation at that interval.  Could probably
		// be done more nicely, but such is life.
		propagate_policies();
		poll_and_dispatch(
		    std::chrono::milliseconds(c_agentino_manager_socket_poll_timeout_ms.get_value()));
	}
}

agentino::ptr agentino_manager::build_agentino(
    connection::ptr connection_in,
    std::map<agentino_metadata_property, std::string> fixed_metadata,
    std::map<std::string, std::string> arbitrary_metadata)
{
	// I'm pretty sure I could use some forwarding magic here
	return agentino::build_agentino(this,
	                                connection_in,
	                                std::move(fixed_metadata),
	                                std::move(arbitrary_metadata));
}

void agentino::send_policies(draiosproto::policies_v2 policies)
{
	return send(draiosproto::message_type::POLICIES_V2, std::move(policies));
}
