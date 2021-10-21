#pragma once

#include "cm_socket.h"
#include "draios.pb.h"
#include "protocol.h"
#include "thread_pool.h"
#include "agent_utils.h"

#include <arpa/inet.h>
#include <cassert>
#include <functional>
#include <memory>
#include <mutex>
#include <queue>
#include <spinlock.h>

namespace agentone
{
class connection_server_owner;
class raw_message;

// Literally an empty class that people can
// inherit from to allow proper destruction at the end of a connection's lifetime
class connection_context
{
public:
	virtual ~connection_context() {}
};

/**
 * Represents the connection between a remote client and this local server
 *
 * The owner must provide callbacks for network events of interest. The order
 * of the invocations is:
 *
 * 1. handle_handshake
 * 2. new_connection
 * 3. delete_connection
 *
 * See the definition of the functions in the connection_server for full details
 */
class connection
{
public:
	using ptr = std::shared_ptr<connection>;

	/**
	 * The result of a network operation; `bool' does not convey enough information.
	 */
	enum result
	{
		SUCCESS,
		CONNECTION_CLOSED,
		FATAL_ERROR,
	};

public:
	/**
	 * Creating the connection object will start running the state machine.
	 */
	connection(cm_socket* sock,
			   connection_server_owner& owner,
	           tp_work_item::client_id client_id);

	~connection();

	/**
	 * Get the server owner associated with this connection.
	 */
	connection_server_owner& get_owner() const { return m_owner; }

	/**
	 * As there is no manager of connections, we maintain a ref on ourselves to
	 * prevent destruction. These functions set and clear that ref.
	 *
	 * The first one must be static as we're setting a shared pointer.
	 *
	 * It is set when we first create the object in the listen work item,
	 * and cleared in disconnect (which might be called multiple times! beware! so a
	 * subsequent call might be null!)
	 */
	static void set_connected_ref(std::shared_ptr<connection>& conn)
	{
		conn->m_connected_ref = conn;
	}
	void clear_connected_ref();

	/**
	 * Set a unique identifier for this connection (to be used in logging, when needed).
	 */
	void set_id(const std::string& id) { m_id = id; }

	/**
	 * Set a name for this connection (to be used in logging, when needed).
	 */
	void set_name(const std::string& name) { m_name = name; }

	/**
	 * Get the previously-set identifier for this connection.
	 */
	const std::string& get_id() const { return m_id; }

	/**
	 * Get the previously-set name for this connection.
	 */
	const std::string& get_name() const { return m_name; }

	/**
	 * Get the thread pool client id for this connection.
	 */
	tp_work_item::client_id get_tp_client_id() const { return m_client_id; }

	/**
	 * Bring up the connection on the server side.
	 *
	 * @param[in] ctx  Context object passed back into the various callbacks.
	 */
	bool start();

	/**
	 * Sends a message to the client.
	 *
	 * This method will block until the message is serialized and transmitted.
	 */
	template<typename PROTOBUF>
	result send_message(draiosproto::message_type type, const PROTOBUF& proto_obj);

	/**
	 * Reads one protocol message from the socket.
	 *
	 * NOTE: Allocates the memory for msg.bytes and transfers ownership of
	 *       that memory to the raw_message parameter. The parameter will
	 *       free that memory on destruction. If that is not the desired
	 *       behavior, the caller should set the buffer_owned field in the
	 *       raw_message to false once this method returns.
	 *
	 * NOTE: Unlike the connection_manager, this code will read the ENTIRE
	 *       message, not returning until the whole message has been read.
	 *       Handle your threading appropriately. If there is no message
	 *       pending, this code will BLOCK YOUR THREAD until there is.
	 */
	result read_message(raw_message& msg);

	/**
	 * Returns the underlying socket for the connection object.
	 *
	 * Why allow everybody such promiscuous access to the internal socket?
	 * Because by doing so we can call poll() on every socket at once
	 * and write more efficient networking code.
	 */
	cm_socket* get_socket();

	/**
	 * The handshake exchange may provide information that the server owner needs later
	 * in the connection's lifetime. These generic functions allow the owner to
	 * stash whatever context it wants to be recovered later. The data stored is
	 * totally opaque to the connection itself, so in theory the owner can use
	 * this for literally whatever it wants. Ownership of the object is transferred during
	 * the set_context call to relieve the server owner of having to free the context. The
	 * contents will remain valid for the life of the connection.
	 *
	 * get_context returns the stored context if handshake has completed, else nullptr
	 */
	const connection_context* get_context();
	void set_context(connection_context* context);

	/**
	 * Disconnect the connection
	 *
	 * Can be called as many times as you like. Cleans up all structures.
	 */
	void disconnect();

private:  // Methods
	/**
	 * Reads the client's handshake message and sends a response.
	 *
	 * Uses the on_handshake callback provided by the server owner to
	 * populate the handshake response.
	 */
	result process_handshake_in();

private:
	cm_socket* m_socket;
	connection_server_owner& m_owner;
	connection_context* m_ctx;
	std::string m_id;
	std::string m_name;

	// This is effectively just a ref between connect and disconnect to ensure
	// we don't go away
	std::shared_ptr<connection> m_connected_ref;

private:  // State machine stuff
	enum fsm_state
	{
		INIT,
		HANDSHAKING,
		FULLY_CONNECTED,
		DISCONNECTED,
	};

	enum fsm_event
	{
		NONE,
		CONNECT,
		DISCONNECT,
		HANDSHAKE_COMPLETE,
		GET_HANDSHAKE_DATA,
	};

	/*
	 * NOTE ON STATE MACHINE
	 * Since the connection object doesn't have its own thread, the FSM can
	 * be reentrant. Some of the normal FSM guarantees are violated. If an FSM
	 * handler function is long-running or blocking, the state of the FSM might
	 * have changed out from under it by the time it completes. Keep this in
	 * mind and all will be well.
	 *
	 * A DISCONNECTED or a GET_HANDSHAKE_DATA event can come in at essentially
	 * any time, even while another FSM operation is occurring. This is the
	 * biggest area of concern. However, it's important to remember that the
	 * connection object does not maintain its own thread but is instead
	 */

	std::atomic<fsm_state> m_state;  // Should only be accessed from inside an FSM function

	/** Identifies this connection as a distinct thread pool client */
	tp_work_item::client_id m_client_id;

	/**
	 * Because the client sends a handshake message immediately upon connect,
	 * handling a connect means handling the handshake.
	 */
	bool handle_connect(fsm_event& chain_evt);

	/**
	 * We can receive a disconnect in any state and it behaves the same.
	 *
	 * This is the most complicated event because it can occur in any state
	 * and it changes the state in its handler. Thus, DISCONNECT can change
	 * the state out from under any other event, even in the middle of event
	 * processing! Although the FSM itself will remain internally consistent
	 * and will process the events correctly, there is the possibility that
	 * the connection object itself could be deleted, which could happen, say,
	 * during a connect callback. Some of these paths will work (i.e. will
	 * unwind without touching internal state). However, a DISCONNECT in the
	 * middle of a handle_connect operation has the possibility to cause a
	 * problem.
	 * I THINK this problem is only theoretical and we're not actually
	 * vulnerable to it. The start() method is called by the thread pool
	 * handler. At this point nobody knows about this connection other than
	 * the thread pool handler, which is off on its own thread doing its own
	 * thing. As the connection does not have its own thread, it will not
	 * initiate any I/O on its own. And since the owner is not
	 * aware of this connection, it will not be able to poke it in any way
	 * (i.e. by disconnecting it). In addition, the work item handler holds a
	 * reference to the connection object for the duration of the CONNECT
	 * processing.
	 *
	 * The owner only becomes aware of the connection on the
	 * transition from HANDSHAKING to FULLY_CONNECTED. Until that time, we do
	 * not have to worry about the connection object being deleted out from
	 * under itself.
	 */
	bool handle_disconnect(fsm_event& chain_evt);

	/**
	 * Handle handshake completion.
	 *
	 * The connection object doesn't run its own network processing loop, so
	 * all we do in this case is notify the client that the connection has
	 * completed.
	 */
	bool handle_handshake_complete(fsm_event& chain_evt);

	/**
	 * Can we service a request for the internally cached handshake data?
	 */
	bool handle_get_handshake_data(fsm_event& chain_evt);

	/**
	 * Handle an event and drive the FSM
	 */
	bool handle_event(fsm_event evt);

	friend class test_helper;
};

template<typename PROTOBUF>
connection::result connection::send_message(draiosproto::message_type type,
                                            const PROTOBUF& proto_obj)
{
	if (!m_socket)
	{
		return FATAL_ERROR;
	}

	auto compressor = protobuf_compressor_factory::get(protocol_compression_method::GZIP);
	// Serialize protobuf
	std::shared_ptr<serialized_buffer> outbuf =
	    dragent_protocol::message_to_buffer(agent_utils::get_current_ts_ns(), type, proto_obj, compressor);
	if (!outbuf)
	{
		return FATAL_ERROR;
	}

	dragent_protocol_header_v5 outhdr = {};
	dragent_protocol::protocol_version version =
	    dragent_protocol::PROTOCOL_VERSION_NUMBER_10S_FLUSH;
	// Fill out the header fields
	uint32_t header_len = dragent_protocol::header_len(version);

	outhdr.hdr.version = version;
	outhdr.hdr.messagetype = outbuf->message_type;
	outhdr.hdr.len = htonl(header_len + outbuf->buffer.size());

	int64_t ret;
	// Send the header first
	ret = m_socket->send((uint8_t*)&outhdr, header_len);
	if (ret < 0)
	{
		return FATAL_ERROR;
	}
	if (ret == 0)
	{
		return CONNECTION_CLOSED;
	}

	// Now send the payload
	ret = m_socket->send((uint8_t*)outbuf->buffer.data(), outbuf->buffer.size());
	if (ret < 0)
	{
		return FATAL_ERROR;
	}
	if (ret == 0)
	{
		return CONNECTION_CLOSED;
	}
	return SUCCESS;
}
}  // namespace agentone
