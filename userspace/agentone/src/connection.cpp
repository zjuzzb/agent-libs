#include "connection.h"
#include "connection_message.h"
#include "connection_server.h"
#include "draios.pb.h"
#include "protocol.h"

#include <cassert>
#include <cerrno>
#include <common_logger.h>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>

// For convenience until this can be moved to a better library
using namespace agentone;

COMMON_LOGGER();

connection::connection(cm_socket* sock,
                       connection_server_owner& owner,
                       tp_work_item::client_id client_id)
    : m_socket(sock),
      m_owner(owner),
      m_ctx(nullptr),
      m_id("<unknown>"),
      m_state(INIT),
      m_client_id(client_id)
{
}

connection::~connection()
{
	disconnect();
	delete m_socket;
	if (m_ctx)
	{
		delete m_ctx;
		m_ctx = nullptr;
	}
}

void connection::clear_connected_ref()
{
	LOG_DEBUG("Clearing ref with refcount %ld", m_connected_ref.use_count());
	m_connected_ref = nullptr;
}

bool connection::start()
{
	bool res = handle_event(CONNECT);

	if (!res)
	{
		LOG_ERROR("Could not establish connection with client");
	}
	return res;
}

cm_socket* connection::get_socket()
{
	return m_socket;
}

void connection::set_context(connection_context* context)
{
	m_ctx = context;
}

const connection_context* connection::get_context()
{
	if (handle_event(GET_HANDSHAKE_DATA))
	{
		return m_ctx;
	}
	return nullptr;
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
		LOG_DEBUG("Connection closed on receive for client name=%s id=%s",
		          m_name.c_str(),
		          m_id.c_str());
		return CONNECTION_CLOSED;
	}

	if (res < 0 || res < sizeof(msg.hdr))
	{
		LOG_ERROR("Unexpected result reading bytes from client name=%s id=%s: %lld (%s)",
		          m_name.c_str(),
		          m_id.c_str(),
		          (long long)res,
		          strerror(errno));
		return FATAL_ERROR;
	}

	if (msg.payload_length() > 0)
	{
		msg.bytes = new uint8_t[msg.payload_length()];
		msg.buffer_owned = true;
	}

	// Now, read body
	uint32_t bytes_read = 0;
	uint32_t bytes_to_read = msg.payload_length();
	result ret = FATAL_ERROR;

	while (bytes_to_read > 0)
	{
		res = m_socket->receive(&msg.bytes[bytes_read], bytes_to_read);

		if (res == 0)
		{
			LOG_DEBUG("Connection closed on receive for client name=%s id=%s",
			          m_name.c_str(),
			          m_id.c_str());
			ret = CONNECTION_CLOSED;
			goto error;
		}

		if (res < 0)
		{
			LOG_ERROR("Error reading bytes from client name=%s id=%s: %lld (%s)",
			          m_name.c_str(),
			          m_id.c_str(),
			          (long long)res,
			          strerror(errno));
			ret = FATAL_ERROR;
			goto error;
		}

		// Check that the arithmetic immediately succeeding won't over/underflow
		if (res + bytes_read > UINT32_MAX || res > bytes_to_read)
		{
			// Should never happen, but don't want to infinite loop
			LOG_ERROR("Receive returned invalid size for client name=%s id=%s size=%lld",
			          m_name.c_str(),
			          m_id.c_str(),
			          (long long)res);
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
	// The handshake starts with a message from the client which should
	// be waiting in the socket for us
	LOG_INFO("Beginning client handshake sequence");
	raw_message msg;
	result res = read_message(msg);
	if (res != SUCCESS)
	{
		if (res == FATAL_ERROR)
		{
			LOG_ERROR("Fatal error reading handshake message from client name=%s id=%s",
			          m_name.c_str(),
			          m_id.c_str());
		}
		return res;
	}

	draiosproto::message_type response_type;
	std::unique_ptr<google::protobuf::MessageLite> response;
	res = m_owner.handle_handshake(m_connected_ref, msg, response, response_type);
	if (res != SUCCESS)
	{
		LOG_ERROR("Fatal error: Handshake callback failed for client name=%s id=%s",
		          m_name.c_str(),
		          m_id.c_str());
		// Handshake rejected. Fail the connection.
		return FATAL_ERROR;
	}

	LOG_INFO("Sending handshake response");
	res = send_message(response_type, *response);

	if (res != SUCCESS)
	{
		if (res == FATAL_ERROR)
		{
			LOG_ERROR("Fatal error sending handshake response to client name=%s id=%s",
			          m_name.c_str(),
			          m_id.c_str());
		}
		else
		{
			LOG_ERROR("Client name=%s id=%s disconnected during handshake reponse phase",
			          m_name.c_str(),
			          m_id.c_str());
		}
	}

	return res;

	// Remember that the buffer allocated in read_message will be automatically
	// freed by the raw_message destructor once this function returns.
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
		LOG_DEBUG("Disconnect received on disconnected socket");
		// We're already disconnected (we do a just-in-case disconnect in the
		// destructor, so this is a normal path to walk down)
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
	m_owner.delete_connection(m_connected_ref);

	// This call can lead to the destruction of the object.
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
			LOG_INFO("Client Successfully connected");
			m_owner.new_connection(m_connected_ref);

			chain_evt = NONE;
			return true;
		}
		else
		{
			// Whoops, state changed out from under us
			// We don't want to call on_connect because the client may have
			// either already received an on_disconnect or may have explicitly
			// disconnected the client itself. An on_connect at this point
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
		LOG_WARNING("Client name=%s id=%s disconnected after handshake completed",
		            m_name.c_str(),
		            m_id.c_str());
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
	LOG_DEBUG("Client name=%s id=%s connection FSM event %d",
	          m_name.c_str(),
	          m_id.c_str(),
	          (int)evt);
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
		LOG_ERROR("Received invalid FSM event for client name=%s id=%s (code error)",
		          m_name.c_str(),
		          m_id.c_str());
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
