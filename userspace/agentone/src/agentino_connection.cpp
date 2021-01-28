#include "agentino_connection.h"

#include <functional>
#include <memory>
#include <cassert>
#include <mutex>

#include <common_logger.h>
#include "protocol.h"
#include "draios.pb.h"
#include "agentino.pb.h"

#include "agentino_message.h"
#include "agentino_manager.h"

using namespace agentone;

COMMON_LOGGER();

const connection::connection_cb connection::empty_callback;

connection::connection(cm_socket* sock,
                       agentone::agentino_manager* manager,
                       handshake_cb on_handshake,
                       connection_cb on_connect,
			           connection_cb on_disconnect)
    : m_socket(sock),
      m_manager(manager),
      m_on_connect(on_connect),
      m_on_disconnect(on_disconnect),
      m_on_handshake(on_handshake),
      m_state(INIT)
{
}

connection::~connection()
{
	disconnect();
	delete m_socket;
}

bool connection::start(void* ctx)
{
	m_ctx = ctx;
	bool res = handle_event(CONNECT);

	if (!res)
	{
		LOG_ERROR("Could not establish connection with agentino");
	}
	return res;
}

cm_socket* connection::get_socket()
{
	return m_socket;
}

bool connection::get_handshake_data(draiosproto::agentino_handshake& hs_data)
{
	if (handle_event(GET_HANDSHAKE_DATA))
	{
		hs_data = m_hs_data;
		return true;
	}
	return false;
}

void connection::disconnect()
{
	handle_event(DISCONNECT);
}

connection::result connection::read_message(raw_message& msg)
{
	if (!m_socket)
	{
		return FATAL_ERROR;
	}
	// First, read header
	int64_t res = m_socket->receive((uint8_t*)&msg.hdr, sizeof(msg.hdr));

	if (res == 0)
	{
		return CONNECTION_CLOSED;
	}

	if (res < 0 || res < sizeof(msg.hdr))
	{
		LOG_ERROR("Unexpected result reading bytes from agentino: %lld", (long long)res);
		return FATAL_ERROR;
	}

	msg.bytes = new uint8_t[msg.payload_length()];
	msg.buffer_owned = true;

	// Now, read body
	uint32_t bytes_read = 0;
	uint32_t bytes_to_read = msg.payload_length();
	result ret = FATAL_ERROR;

	while (bytes_to_read > 0)
	{
		res = m_socket->receive(&msg.bytes[bytes_read], bytes_to_read);

		if (res == 0)
		{
			ret = CONNECTION_CLOSED;
			goto error;
		}

		if (res < 0)
		{
			LOG_ERROR("Error reading bytes from agentino: %lld", (long long)res);
			ret = FATAL_ERROR;
			goto error;
		}

		// Check that the arithmetic immediately succeeding won't over/underflow
		if (res + bytes_read > UINT32_MAX || res > bytes_to_read)
		{
			// Should never happen, but don't want to infinite loop
			LOG_ERROR("Receive returned invalid size %lld", (long long)res);
			ret = FATAL_ERROR;
			goto error;
		}

		bytes_read += res;
		bytes_to_read -= res;
	}

	return SUCCESS;

error:
	delete[] msg.bytes;
	return ret;
}

connection::result connection::process_handshake_in()
{
	// The handshake starts with a message from the agentino which should
	// be waiting in the socket for us
	LOG_INFO("Beginning agentino handshake sequence");
	raw_message msg;
	result res = read_message(msg);
	if (res != SUCCESS)
	{
		if (res == FATAL_ERROR)
		{
			LOG_ERROR("Fatal error reading handshake message from agentino.");
		}
		else
		{
			LOG_ERROR("Agentino disconnected during handshake.");
		}
		return res;
	}

	LOG_DEBUG("Deserializing handshake protobuf");
	try
	{
		dragent_protocol::buffer_to_protobuf(msg.bytes,
		                                     msg.payload_length(),
		                                     &m_hs_data);
	}
	catch (const dragent_protocol::protocol_error& e)
	{
		LOG_ERROR("Protocol error: could not parse handshake message");
		return FATAL_ERROR;
	}

	// Now m_hs_data contains the handshake protobuf. The on_handshake callback
	// will send the protobuf to the client and get the response protobuf in
	// return
	draiosproto::agentino_handshake_response resp;
	if (!m_on_handshake)
	{
		LOG_ERROR("Code error: Missing callback for handshake response");
		return FATAL_ERROR;
	}
	bool ret = m_on_handshake(m_manager, m_ctx, m_hs_data, resp);
	if (!ret)
	{
		LOG_ERROR("Fatal error: Handshake callback failed");
		// Handshake rejected. Fail the connection.
		return FATAL_ERROR;
	}

	LOG_INFO("Sending handshake response");
	res = send_message(draiosproto::message_type::AGENTINO_HANDSHAKE_RESPONSE,
	                   resp);
	if (res != SUCCESS)
	{
		if (res == FATAL_ERROR)
		{
			LOG_ERROR("Fatal error sending handshake response to agentino.");
		}
		else
		{
			LOG_ERROR("Agentino disconnected during handshake reponse phase.");
		}
		return res;
	}
	return SUCCESS;

	// Remember that the buffer allocated in read_message will be automatically
	// freed by the raw_message destructor once this function returns.
}

uint64_t connection::get_current_ts()
{
	return agentone::agentino_manager::get_current_ts_ns();
}

/*****************************************************************************
 * State machine
 *****************************************************************************/

bool connection::handle_connect(connection::fsm_event& chain_evt)
{
	result s;
	fsm_state curr_state = m_state;
	bool success;
	switch (curr_state)
	{
	case INIT:
		success = m_state.compare_exchange_strong(curr_state, HANDSHAKING);
		if (success)
		{
			s = process_handshake_in();
			if (s == SUCCESS)
			{
				chain_evt = HANDSHAKE_COMPLETE;
			}
			else
			{
				chain_evt = DISCONNECT;
			}
			return true;
		}
		else
		{
			// Very unlikely to have state changed out from under us in INIT
			// state. Probably indicates a bug.
			LOG_ERROR("Unexpected transition from INIT state to %d", (int)curr_state);
			return false;
		}
	case HANDSHAKING:
	case FULLY_CONNECTED:
	case DISCONNECTED:
		LOG_ERROR("Connect received in unexpected state %d", (int)m_state);
		// Shouldn't be possible. Major bug.
		return false;
	}
	return false;
}

bool connection::handle_disconnect(connection::fsm_event& chain_evt)
{
	chain_evt = NONE;
	if (m_state == DISCONNECTED)
	{
		// We're already disconnected
		return true;
	}

	if (m_socket)
	{
		// Reasons we might not have a socket:
		// 1. This is a unit test and we're using a fake connection
		// 2. ???
		m_socket->close();
	}
	m_state = DISCONNECTED;
	if (m_on_disconnect)
	{
		m_on_disconnect(m_manager, m_connected_ref, m_ctx);
	}

	// This can lead to destruction of this object, but this should only ever be called
	// once
	clear_connected_ref();
	return true;
}

bool connection::handle_handshake_complete(connection::fsm_event& chain_evt)
{
	fsm_state curr_state = m_state;
	bool success;
	switch (curr_state)
	{
	case HANDSHAKING:
		// Handshake is done on our side
		success = m_state.compare_exchange_strong(curr_state, FULLY_CONNECTED);
		if (success)
		{
			LOG_INFO("Agentino Successfully connected");
			if (m_on_connect)
			{
				m_on_connect(m_manager, m_connected_ref, m_ctx);
			}
			chain_evt = NONE;
			return true;
		}
		else
		{
			// Whoops, state changed out from under us
			// We don't want to call on_connect because the client may have
			// either already received an on_disconnect or may have explicitly
			// disconnected the agentino itself. An on_connect at this point
			// would be misleading.
			return false;
		}
	case INIT:
	case FULLY_CONNECTED:
		// Given that handshake complete is an internally-generated
		// event, it doesn't really make sense for us to receive it in
		// a state other than HANDSHAKING.
		LOG_ERROR("Expected state %d, got state %d", (int)HANDSHAKING, (int)m_state);
		return false;
	case DISCONNECTED:
		LOG_WARNING("Agentino disconnected after handshake completed");
		return false;
	}
	LOG_ERROR("Code error: Handshake completed in unexpected state %d", (int)m_state);
	return false;
}

bool connection::handle_get_handshake_data(connection::fsm_event& chain_evt)
{
	chain_evt = NONE;
	switch (m_state)
	{
	case HANDSHAKING:
	case FULLY_CONNECTED:
		return true;
	case INIT:
	case DISCONNECTED:
		return false;
	}
	return false;
}

bool connection::handle_event(connection::fsm_event evt)
{
	LOG_DEBUG("Agentino connection FSM event %d", (int)evt);
	fsm_event chain_evt = fsm_event::NONE;
	bool ret = false;
	switch (evt)
	{
	case CONNECT:
		ret = handle_connect(chain_evt);
		break;
	case DISCONNECT:
		ret = handle_disconnect(chain_evt);
		break;
	case HANDSHAKE_COMPLETE:
		ret = handle_handshake_complete(chain_evt);
		break;
	case GET_HANDSHAKE_DATA:
		ret = handle_get_handshake_data(chain_evt);
		break;
	case NONE:
		LOG_ERROR("Received invalid FSM event (code error)");
		assert("Invalid FSM event" == 0);
		return false;
	}

	if (!ret)
	{
		return false;
	}

	if (chain_evt != fsm_event::NONE)
	{
		return handle_event(chain_evt);
	}
	return true;
}
