#include "agent_utils.h"
#include "agentino.pb.h"
#include "agentino_manager.h"
#include "connection_message.h"
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
type_config<uint64_t> c_thread_sleep_interval_ms(
    1000,
    "Amount of time thread sleeps if there is currently no work to do",
    "agentino_manager",
    "thread_sleep_interval_ms");
COMMON_LOGGER();
}  // namespace

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
                                   protocol_queue* transmit_queue,
                                   container_manager& container_manager_in,
                                   const std::string& machine_id,
                                   const std::string& customer_id)
    : m_container_manager(container_manager_in),
      m_shutdown(false),
      m_policies_valid(false),
      m_events_handler(events_handler),
      m_transmit_queue(transmit_queue),
      m_policies_updated(false),
      m_machine_id(machine_id),
      m_customer_id(customer_id),
      m_thread(&agentino_manager::run, this),
      m_connection_server(*this, c_agentino_port.get_value(), c_agentino_ssl.get_value())
{
	m_connection_server.start();
}

agentino_manager::~agentino_manager()
{
	if (!m_shutdown)
	{
		m_shutdown = true;
		m_connection_server.stop();
		m_thread.join();
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

void agentino_manager::new_connection(connection::ptr& connection_in)
{
	std::lock_guard<std::mutex> lock(m_agentino_list_lock);
	std::map<agentino_metadata_property, std::string> fixed_metadata;

	const agentino_handshake_connection_context* context =
	    dynamic_cast<const agentino_handshake_connection_context*>(connection_in->get_context());
	if (context == nullptr)
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
	agentino_manager::build_metadata(context->request, fixed_metadata, arbitrary_metadata);

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
		extant_agentino =
		    build_agentino(connection_in, std::move(fixed_metadata), std::move(arbitrary_metadata));
		m_agentinos.insert(extant_agentino);
		m_agentinos_by_connection.emplace(connection_in, extant_agentino);
	}

	connection_in->set_id(extant_agentino->get_id());
	connection_in->set_name(extant_agentino->get_name());
	// to be picked up by the agentino_manager thread to ensure we have most recent policies
	m_new_agentinos.push_back(extant_agentino);
}

void agentino_manager::delete_connection(connection::ptr& connection_in)
{
	std::lock_guard<std::mutex> lock(m_agentino_list_lock);

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

void agentino_manager::get_pollable_connections(std::list<connection::ptr>& out) const
{
	out.clear();
	std::lock_guard<std::mutex> lock(m_agentino_list_lock);

	for (auto& agentino : m_agentinos)
	{
		auto listenable_connection = agentino->get_connection_info();
		if (listenable_connection != nullptr)
		{
			out.emplace_back(listenable_connection);
		}
	}
}

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

		// Make sure we know that we've received policies
		m_policies_valid = true;
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

		uint64_t time_ns = agent_utils::get_current_ts_ns();
		// Need to set machine ID / customer ID to match agentone, as that's
		// what backend expects
		events.set_machine_id(m_machine_id);
		events.set_customer_id(m_customer_id);
		m_events_handler.security_mgr_policy_events_ready(time_ns, &events);
		return true;
	}
	else if (type == draiosproto::message_type::THROTTLED_POLICY_EVENTS)
	{
		uint32_t num_throttled_events = 0;
		draiosproto::throttled_policy_events tevents;
		try
		{
			dragent_protocol::buffer_to_protobuf(buffer, buffer_size, &tevents);
		}
		catch (dragent_protocol::protocol_error& ex)
		{
			LOG_ERROR("Protocol error while parsing events message: %s", ex.what());
			return false;
		}

		uint64_t time_ns = agent_utils::get_current_ts_ns();
		// Need to set machine ID / customer ID to match agentone, as that's
		// what backend expects
		tevents.set_machine_id(m_machine_id);
		tevents.set_customer_id(m_customer_id);

		// The correct way to implement this is to walk through every event in
		// the list of throttled events, add up the counts, and that's the total.
		// However, this number is only cosmetic, and it's not really worth the
		// CPU cycles to do so.
		m_events_handler.security_mgr_throttled_events_ready(time_ns,
		                                                     &tevents,
		                                                     num_throttled_events);
		return true;
	}
	else if (type == draiosproto::message_type::DUMP_RESPONSE)
	{
		draiosproto::dump_response dump_resp;
		try
		{
			dragent_protocol::buffer_to_protobuf(buffer, buffer_size, &dump_resp);
		}
		catch (dragent_protocol::protocol_error& ex)
		{
			LOG_ERROR("Protocol error while parsing dump response message: %s", ex.what());
			return false;
		}

		// Need to set machine ID / customer ID to match agentone, as that's
		// what backend expects
		dump_resp.set_machine_id(m_machine_id);
		dump_resp.set_customer_id(m_customer_id);

		if (forward_dump_response(dump_resp))
		{
			LOG_DEBUG("Sent dump response chunk to connection manager");
		}
		else
		{
			LOG_WARNING("Queue full attempting to forward dump response to collector; discarding.");
			return false;
		}

		return true;
	}
	else
	{
		LOG_ERROR("Agentino manager received unexpected message of type %d. Ignoring", type);
		return false;
	}
}

bool agentino_manager::forward_dump_response(draiosproto::dump_response& dresp)
{
	std::shared_ptr<protobuf_compressor> compressor;
	compressor = gzip_protobuf_compressor::get(-1);

	// Serialize
	std::shared_ptr<serialized_buffer> buf;
	try
	{
		buf = dragent_protocol::message_to_buffer(agent_utils::get_current_ts_ns(),
		                                          draiosproto::message_type::DUMP_RESPONSE,
		                                          dresp,
		                                          compressor);
	}
	catch (dragent_protocol::protocol_error& ex)
	{
		LOG_ERROR("Could not serialize dump response: %s", ex.what());
		return false;
	}

	if (!buf)
	{
		LOG_ERROR("Could not serialize dump response.");
		return false;
	}

	// Send
	return m_transmit_queue->put(buf, protocol_queue::BQ_PRIORITY_LOW);
}

bool agentino_manager::propagate_policies()
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

	return made_policy_copy;
}

connection::result agentino_manager::handle_handshake(
    connection::ptr& conn,
    const raw_message& message,
    std::unique_ptr<google::protobuf::MessageLite>& response,
    draiosproto::message_type& response_type)
{
	auto request_context = new agentino_handshake_connection_context();
	LOG_DEBUG("Deserializing handshake protobuf");

	try
	{
		dragent_protocol::buffer_to_protobuf(message.bytes,
		                                     message.payload_length(),
		                                     &request_context->request);
	}
	catch (const dragent_protocol::protocol_error& e)
	{
		LOG_ERROR("Protocol error: could not parse handshake message from agentino");
		return connection::FATAL_ERROR;
	}

	bool is_valid = false;
	// Validate the input proto
	uint64_t ts_in = request_context->request.timestamp_ns();
	if (ts_in > 0)
	{
		is_valid = true;
	}

	/// Validation happens here, but won't be any validation in v1
	// SMAGENT-2861
	if (!is_valid)
	{
		LOG_ERROR("Invalid handshake protobuf from agentino");
		return connection::FATAL_ERROR;
	}

	// SSPROD-8535: Don't accept incoming agentino connections until
	// we actually have valid policies loaded. Otherwise we end up sending
	// an empty policy set to the agentino and it starts the workload
	// assuming those policies are valid.
	if (!m_policies_valid)
	{
		LOG_WARNING("Rejecting agentino connection because policies not loaded yet. "
		            "Check the backend connection.");
		return connection::FATAL_ERROR;
	}

	// Populate the output proto
	response.reset(new draiosproto::agentino_handshake_response);
	draiosproto::agentino_handshake_response* typed_response = dynamic_cast<draiosproto::agentino_handshake_response*>(&*response); // god help us if this cast fails...
	response_type = draiosproto::message_type::AGENTINO_HANDSHAKE_RESPONSE;
	typed_response->set_timestamp_ns(agent_utils::get_current_ts_ns());
	m_policies_lock.lock();
	typed_response->mutable_policies()->CopyFrom(m_cached_policies);
	m_policies_lock.unlock();

	// If the send failed, we'll let someone else deal with cleaning this up
	conn->set_context(request_context);

	return connection::SUCCESS;
}

void agentino_manager::run()
{
	while (!m_shutdown)
	{
		bool did_work = false;

		did_work |= propagate_policies();

		if (!did_work)
		{
			std::this_thread::sleep_for(
			    std::chrono::milliseconds(c_thread_sleep_interval_ms.get_value()));
		}
	}
}

agentino::ptr agentino_manager::build_agentino(
    connection::ptr connection_in,
    const std::map<agentino_metadata_property, std::string>& fixed_metadata,
    const std::map<std::string, std::string>& arbitrary_metadata)
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
