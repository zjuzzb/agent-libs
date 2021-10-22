#pragma once
#include "connection.h"
#include "connection_manager.h"  // message_handler
#include "draios.pb.h"
#include "thread_pool.h"

#include <list>
#include <memory>

/**
 * This infrastructure provides the ability for a module to act as a server. It does so
 * by deriving from the connection_server_owner class, and implementing the virtual functions.
 *
 * The module should then create and start an instance of the connection_server,
 * which will make the appropriate callbacks. The owner should NOT take matters
 * of connection management into its own hands, and in general, should only
 * be using send_message and the set_METADATA APIs. Owners should never be calling
 * "disconnect" of their own accord, for instance.
 *
 * See the agentino_manager for a reference implementation.
 *
 * NOTE: the cm_socket which backs this infrastructure has major issues on shutdown
 * if there are multiple clients of that infrastructure. See SMAGENT-2952
 */
namespace agentone
{
class raw_message;

/**
 * The owner of a connection server. Ultimately, the module who needs the server to
 * exist, and who the server will call back when events occur on the server
 */
class connection_server_owner : public connection_manager::message_handler
{
public:
	/**
	 * function called during handshake, allowing owner to populate response data.
	 * return SUCCESS if we believe the connection should be accepted, FATAL_ERROR otherwise.
	 * response is expected to be set in SUCCESS case, and not in FATAL_ERROR case.
	 *
	 * @param[in] conn the connection for this handshake
	 * @param[in] message the first message on the connection, which should be a handshake request
	 * @param[out] response the response message to the handshake. should be set via
	 *                      response.reset(new draiosproto::WHATEVER_MESSAGE_TYPE).
	 *                      should only be set if the return value is SUCCESS, otherwise,
	 *                      leave untouched
	 * @param[out] response_type the message type matching the derived type of response
	 */
	virtual connection::result handle_handshake(
	    connection::ptr& conn,
	    const raw_message& message,
	    std::unique_ptr<google::protobuf::MessageLite>& response,
	    draiosproto::message_type& response_type) = 0;

	/**
	 * called at completion of a handshake, when the connection is fully established
	 */
	virtual void new_connection(connection::ptr& conn) = 0;

	/**
	 * called when a connection is broken on either end.
	 */
	virtual void delete_connection(connection::ptr& conn) = 0;

	/**
	 * called to request a list of connections on which the owner wants the server
	 * to poll. The owner should ONLY put connections on this list which have had
	 * calls to "new_connection" made but not "delete_connection." Placing any
	 * other connections in this list is undefined behavior. Note: not ALL connections
	 * are necessarily required to be in this list
	 */
	virtual void get_pollable_connections(std::list<connection::ptr>& out) const = 0;

public:  // message_handler
	virtual bool handle_message(draiosproto::message_type type,
	                            const uint8_t* buffer,
	                            size_t buffer_size) override = 0;
};

/**
 * the actual connection server. It juggles the minutiae of handling connections
 * so the server owner can focus on the actual businesss logic of what to do
 * when connections happen and send messages
 */
class connection_server
{
public:
	connection_server(connection_server_owner& owner, uint16_t port, bool use_ssl);
	~connection_server();

	/**
	 * starts the server. the server must be started before it will do anything.
	 */
	void start();

	/**
	 * stops the server. The server will guarantee that no callbacks happen
	 * after the server has been stopped
	 */
	void stop();

private:
	void listen();
	void stop_listening();
	void run();
	void poll_and_dispatch(std::chrono::milliseconds timeout);

private:
	connection_server_owner& m_owner;
	uint16_t m_port;
	bool m_use_ssl;

	bool m_started;
	bool m_shutdown;
	thread_pool m_pool;
	std::thread m_thread;
};
}  // namespace agentone
