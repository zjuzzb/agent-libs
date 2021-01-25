#pragma once

#include "agentino.pb.h"
#include "agentino_message.h"
#include "cm_socket.h"
#include "draios.pb.h"
#include "protocol.h"

#include <arpa/inet.h>
#include <cassert>
#include <functional>
#include <memory>
#include <mutex>
#include <queue>
#include <spinlock.h>

namespace agentone
{
class agentino_manager;
class agentino;

/**
 * Represents the connection between the agentone and the agentino.
 *
 * The client registers callbacks for network events of interest. The order
 * of the callbacks is:
 *
 * 1. on_handshake: [required] Provides the handshake data and receives the
 *                             handshake response data.
 * 2. on_connect: [optional] Notifies that the connection is fully established
 *                           (handshake complete).
 * 3. on_disconnect: [optional] Notifies the client of disconnect (on either end).
 */
class connection
{
public:
	using ptr = std::shared_ptr<connection>;
	using connection_cb = std::function<void(agentone::agentino_manager*, std::shared_ptr<connection>, void*)>;
	using handshake_cb = std::function<bool(agentone::agentino_manager*,
	                                        void*,
	                                        const draiosproto::agentino_handshake&,
	                                        draiosproto::agentino_handshake_response&)>;

	/**
	 * The result of a network operation; `bool' does not convey enough information.
	 */
	enum result
	{
		SUCCESS,
		CONNECTION_CLOSED,
		FATAL_ERROR,
	};

	static const connection_cb empty_callback;

public:
	/**
	 * Creating the connection object will start running the state machine.
	 */
	connection(cm_socket* sock,
	           agentone::agentino_manager* manager,
	           handshake_cb on_handshake,
	           connection_cb on_connect = empty_callback,
	           connection_cb on_disconnect = empty_callback);

	~connection();

	/**
	 * Get the agentino manager associated with this connection.
	 */
	agentone::agentino_manager* get_manager() const { return m_manager; }

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
	static void set_connected_ref(std::shared_ptr<connection>& conn) { conn->m_connected_ref = conn; }
	void clear_connected_ref() { m_connected_ref = nullptr; }

	/**
	 * Bring up the connection on the agentone side.
	 *
	 * @param[in] ctx  Context object passed back into the various callbacks.
	 */
	bool start(void* ctx);

	/**
	 * Sends a message to the agentino.
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
	 * Because by doing so we can call poll() on every agentino socket at once
	 * and write more efficient networking code.
	 */
	cm_socket* get_socket();

	/**
	 * Provide the handshake data, if a handshake has been completed.
	 *
	 * This event does need a bit more work because it is vulnerable in the
	 * future to a use-after-free bug. We are not currently vulnerable to this
	 * bug because the agentino_manager is holding the map lock while it calls
	 * the get_handshake_data function, so there's no possibility of the
	 * handshake data disappearing out from under the caller.
	 */
	bool get_handshake_data(draiosproto::agentino_handshake& hs_data);

	/**
	 * Disconnect the connection from the agentino.
	 *
	 * Can be called as many times as you like. Cleans up all structures.
	 */
	void disconnect();

private:  // Methods
	/**
	 * Reads the agentino's handshake message and sends a response.
	 *
	 * Uses the on_handshake callback provided by the client of this class to
	 * populate the handshake response.
	 */
	result process_handshake_in();

	/**
	 * Get the current timestamp, in nanoseconds
	 */
	uint64_t get_current_ts();

private:
	cm_socket* m_socket;
	agentone::agentino_manager* m_manager;
	connection_cb m_on_connect;
	connection_cb m_on_disconnect;
	handshake_cb m_on_handshake;
	draiosproto::agentino_handshake m_hs_data;
	void* m_ctx;

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

	/**
	 * Because the agentino sends a handshake message immediately upon connect,
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
	 * initiate any I/O on its own. And since the agentino_manager is not
	 * aware of this connection, it will not be able to poke it in any way
	 * (i.e. by disconnecting it). In addition, the work item handler holds a
	 * reference to the connection object for the duration of the CONNECT
	 * processing.
	 *
	 * The agentino manager only becomes aware of the connection on the
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
	    dragent_protocol::message_to_buffer(get_current_ts(), type, proto_obj, compressor);
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
