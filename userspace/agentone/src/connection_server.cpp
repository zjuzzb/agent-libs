#include "common_logger.h"
#include "connection_message.h"
#include "connection_server.h"
#include "type_config.h"

COMMON_LOGGER();

namespace
{
type_config<uint64_t> c_socket_poll_timeout_ms(
    300,
    "the amount of time the socket poll waits before returning",
    "connection_server",
    "socket_poll_timeout_ms");

type_config<uint16_t>::ptr c_thread_pool_size =
    type_config_builder<uint16_t>(
        2,
        "Number of threads in each instance of the connection server's thread pool.",
        "connection_server",
        "thread_pool_size")
        .min(1)
        .hidden()
        .build();
}  // namespace

// This will save effort when this moves out of the agentone
using namespace agentone;

connection_server::connection_server(connection_server_owner& owner, uint16_t port, bool use_ssl)
    : m_owner(owner),
      m_port(port),
      m_use_ssl(use_ssl),
      m_started(false),
      m_shutdown(false),
      m_pool(c_thread_pool_size->get_value())
{
}

connection_server::~connection_server()
{
	stop();
}

void connection_server::start()
{
	if (!m_started && !m_shutdown)
	{
		m_started = true;
		listen();
		m_thread = std::thread(&connection_server::run, this);
	}
}

void connection_server::stop()
{
	if (!m_shutdown)
	{
		m_shutdown = true;
		m_thread.join();
		if (m_started)
		{
			stop_listening();
		}
	}
}

/**
 * Thread pool work item for completing client connection.
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
		if (!m_conn_ctx->start())
		{
			LOG_ERROR("Failed to connect to new client");
		}
	}

private:
	connection::ptr m_conn_ctx;
};

class message_work_item : public tp_work_item
{
public:
	message_work_item(connection_server_owner& owner, raw_message& msg, client_id id)
	    : tp_work_item(id),
	      m_owner(owner),
	      m_msg(msg)
	{
	}

	virtual void handle_work() override
	{
		draiosproto::message_type type =
		    static_cast<draiosproto::message_type>(m_msg.hdr.hdr.messagetype);

		LOG_INFO("Handling message of type %d", (int)type);
		// Dispatch the message
		(void)m_owner.handle_message(type, m_msg.bytes, m_msg.payload_length());
	}

private:
	connection_server_owner& m_owner;
	raw_message m_msg;
};

void connection_server::listen()
{
	auto new_conn_cb = [this](cm_socket* sock, void* ctx)
	{
		// Translate the socket into a connection object
		connection::ptr connp =
		    std::make_shared<connection>(sock, m_owner, m_pool.build_new_client_id());

		// Complete the connection on a thread pool thread
		m_pool.submit_work(new listen_work_item(connp));
	};

	auto conn_error_cb = [this](cm_socket::error_type et, int error, void* ctx)
	{
		LOG_ERROR("Listening for client connections failed: %d, %d", (int)et, (int)error);

		// We're going to try again now
		listen();
	};

	bool ret = cm_socket::listen({m_port, m_use_ssl}, new_conn_cb, conn_error_cb, this);
	if (!ret)
	{
		LOG_ERROR("Could not listen for client connections");
	}
}

void connection_server::stop_listening()
{
	// This is very broken with multiple clients
	// SMAGENT-2952
	cm_socket::stop_listening(true);
}

void connection_server::poll_and_dispatch(std::chrono::milliseconds timeout)
{
	std::list<std::shared_ptr<connection>> conn_list;
	std::list<cm_socket::poll_sock> sock_list;
	std::list<cm_socket::poll_sock> ready_list;

	// Note: it is not possible for a connection to die between getting the connection from
	// the owner and listening on the socket. This is as the ONLY calls to connection
	// disconnect happen on a failure to poll, which conveniently only happens in this
	// function, on this thread. So it is guaranteed to not go away.
	//
	// Note that this means that if there is a connection we are only SENDING on, we
	// might not know it is dead until we decide we need to poll it. Either way,
	// the owner should not take matters into its own hands and call "disconnect"
	m_owner.get_pollable_connections(conn_list);
	for (auto& conn : conn_list)
	{
		auto socket = conn->get_socket();
		if (socket)
		{
			sock_list.emplace_back(socket, new connection::ptr(conn));
		}
	}

	if (sock_list.empty())
	{
		// The run loop is relying on this function to sleep in order to not
		// busy wait. In the case where there are no clients connected, we
		// will sleep for the entire timeout value.
		// Note that this will not impact our ability to receive new client
		// connections, as that occurs on the listen thread. So by sleeping
		// in the zero-connected-client case we are not jeopardizing our
		// ability to respond to an incoming connection.
		//
		// This could probably be smarter if we slept this thread on a semaphore until
		// there were new connections.
		std::this_thread::sleep_for(timeout);
		return;
	}

	bool ret = cm_socket::poll(sock_list, ready_list, timeout);

	if (!ret)
	{
		LOG_ERROR("Communications error: Could not poll for client messages");
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
			if (type == draiosproto::message_type::AGENT_SERVER_HEARTBEAT)
			{
				// Heartbeat message, nothing to do here
				LOG_DEBUG("Received heartbeat from client name=%s id=%s",
				          (*cptr)->get_name().c_str(),
				          (*cptr)->get_id().c_str());
			}
			else
			{
				LOG_INFO("Read message of type %d and length %u from client name=%s id=%s",
				         (int)type,
				         msg.payload_length(),
				         (*cptr)->get_name().c_str(),
				         (*cptr)->get_id().c_str());

				// Submit work queue item to deserialize and dispatch
				m_pool.submit_work(
				    new message_work_item(m_owner, msg, (*cptr)->get_tp_client_id()));
			}
		}
		else
		{
			LOG_WARNING(
			    "Error reading message from client"
			    "(probably client disconnected) name=%s id=%s",
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
		// The corresponding allocation is earlier in this function when we build
		// the sock list
		std::shared_ptr<connection>* cptr = (connection::ptr*)psock.ctx;
		delete cptr;
	}
}

void connection_server::run()
{
	while (!m_shutdown)
	{
		poll_and_dispatch(
		    std::chrono::milliseconds(c_socket_poll_timeout_ms.get_value()));
	}
}
