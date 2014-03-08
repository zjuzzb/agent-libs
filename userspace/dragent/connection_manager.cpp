#include "connection_manager.h"

#include "logger.h"
#include "protocol.h"
#include "draios.pb.h"
#include "ssh_worker.h"
#include "update_worker.h"

const string connection_manager::m_name = "connection_manager";

connection_manager::connection_manager(dragent_configuration* configuration, 
		protocol_queue* queue, sinsp_worker* sinsp_worker):
	m_sa(NULL),
	m_socket(NULL),
	m_buffer(RECEIVER_BUFSIZE),
	m_configuration(configuration),
	m_queue(queue),
	m_sinsp_worker(sinsp_worker)
{
	Poco::Net::initializeSSL();	
}

connection_manager::~connection_manager()
{
	Poco::Net::uninitializeSSL();
}

bool connection_manager::init()
{
	if(m_configuration->m_server_addr != "" && m_configuration->m_server_port != 0)
	{
		m_sa = new Poco::Net::SocketAddress(m_configuration->m_server_addr, m_configuration->m_server_port);

		if(m_configuration->m_ssl_enabled)
		{
			g_log->information("SSL enabled, initializing context");

			Poco::Net::Context::Ptr ptrContext = new Poco::Net::Context(
				Poco::Net::Context::CLIENT_USE, 
				"", 
				"", 
				m_configuration->m_ssl_ca_certificate, 
				Poco::Net::Context::VERIFY_STRICT, 
				9, 
				false, 
				"ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");

			Poco::Net::SSLManager::instance().initializeClient(0, 0, ptrContext);
		}

		return true;
	}
	else
	{
		g_log->warning("Server address has not been specified");
		return false;
	}
}

bool connection_manager::connect()
{
	try
	{
		ASSERT(m_socket.isNull());
		ASSERT(!m_sa.isNull());

		g_log->information("Connecting to collector");

		if(m_configuration->m_ssl_enabled)
		{
			m_socket = new Poco::Net::SecureStreamSocket();

			((Poco::Net::SecureStreamSocket*) m_socket.get())->setLazyHandshake(true);
			((Poco::Net::SecureStreamSocket*) m_socket.get())->setPeerHostName(m_configuration->m_server_addr);
			((Poco::Net::SecureStreamSocket*) m_socket.get())->connect(*m_sa, SOCKET_TIMEOUT_DURING_CONNECT_US);
		}
		else
		{
			m_socket = new Poco::Net::StreamSocket();
			m_socket->connect(*m_sa, SOCKET_TIMEOUT_DURING_CONNECT_US);
		}

		if(m_configuration->m_ssl_enabled)
		{
			//
			// This is done to prevent getting stuck forever waiting during the handshake
			// if the server doesn't speak to us
			//
			m_socket->setSendTimeout(SOCKET_TIMEOUT_DURING_CONNECT_US);
			m_socket->setReceiveTimeout(SOCKET_TIMEOUT_DURING_CONNECT_US);

			int32_t ret = ((Poco::Net::SecureStreamSocket*) m_socket.get())->completeHandshake();
			if(ret != 1)
			{
				g_log->error(m_name + ": SSL Handshake didn't complete");
				disconnect();
				return false;
			}

			((Poco::Net::SecureStreamSocket*) m_socket.get())->verifyPeerCertificate();

			g_log->information("SSL identity verified");
		}

		//
		// Set the send buffer size for the socket
		//
		m_socket->setSendBufferSize(m_configuration->m_transmitbuffer_size);
		m_socket->setSendTimeout(SOCKET_TIMEOUT_AFTER_CONNECT_US);
		m_socket->setReceiveTimeout(SOCKET_TIMEOUT_AFTER_CONNECT_US);

		g_log->information("Connected to collector");
		return true;
	}
	catch(Poco::IOException& e)
	{
		g_log->error(m_name + ": " + e.displayText());
		disconnect();
		return false;
	}
}

void connection_manager::disconnect()
{
	if(!m_socket.isNull())
	{
		m_socket->close();
		m_socket = NULL;
	}
}

void connection_manager::run()
{
	g_log->information(m_name + ": Starting");

	SharedPtr<protocol_queue_item> item;

	while(!dragent_configuration::m_terminate)
	{
		//
		// Make sure we have a valid connection
		//
		if(m_socket.isNull())
		{
			Thread::sleep(1000);
			
			if(!connect())
			{
				continue;
			}
		}

		if(item.isNull())
		{
			//
			// Wait 100ms to get a message from the queue
			//
			m_queue->get(&item, 100);
		}

		if(!item.isNull())
		{
			//
			// Got a message, transmit it
			//
			if(transmit_buffer(item->data(), item->size()))
			{
				item = NULL;
			}
		}

		//
		// Check if we received a message
		//
		receive_message();
	}

	g_log->information(m_name + ": Terminating");
}

bool connection_manager::transmit_buffer(const char* buffer, uint32_t buflen)
{
	try
	{
		if(m_socket.isNull())
		{
			return false;
		}

		int32_t res = m_socket->sendBytes(buffer, buflen);
		if(res == Poco::Net::SecureStreamSocket::ERR_SSL_WANT_WRITE)
		{
			return false;
		}

		if(res != (int32_t) buflen)
		{
			g_log->error(m_name + ": sendBytes sent just " 
				+ NumberFormatter::format(res) 
				+ ", expected " + NumberFormatter::format(buflen));	

			disconnect();

			ASSERT(false);
			return false;
		}

		g_log->debug(m_name + ": Sent " 
			+ Poco::NumberFormatter::format(buflen) + " to collector");

		return true;
	}
	catch(Poco::IOException& e)
	{
		g_log->error(m_name + ": " + e.displayText());
		disconnect();
	}
	catch(Poco::TimeoutException& e)
	{
	}

	return false;
}

void connection_manager::receive_message()
{
	try
	{
		if(m_socket.isNull())
		{
			return;
		}

		int32_t res = m_socket->receiveBytes(m_buffer.begin(), sizeof(dragent_protocol_header), MSG_WAITALL);
		if(res == Poco::Net::SecureStreamSocket::ERR_SSL_WANT_READ)
		{
			return;
		}

		if(res == 0)
		{
			g_log->error(m_name + ": Lost connection (1)");
			disconnect();
			return;
		}

		if(res != sizeof(dragent_protocol_header))
		{
			g_log->error(m_name + ": Protocol error (1): " + NumberFormatter::format(res));
			ASSERT(false);
			disconnect();
			return;
		}

		dragent_protocol_header* header = (dragent_protocol_header*) m_buffer.begin();
		header->len = ntohl(header->len);

		if(header->len > RECEIVER_BUFSIZE)
		{
			g_log->error(m_name + ": Protocol error (2): " + NumberFormatter::format(header->len));
			ASSERT(false);
			disconnect();
			return;						
		}

		if(header->len < sizeof(dragent_protocol_header))
		{
			g_log->error(m_name + ": Protocol error (3): " + NumberFormatter::format(header->len));
			ASSERT(false);
			disconnect();
			return;
		}

		res = m_socket->receiveBytes(
			m_buffer.begin() + sizeof(dragent_protocol_header), 
			header->len - sizeof(dragent_protocol_header), 
			MSG_WAITALL);

		if(res == Poco::Net::SecureStreamSocket::ERR_SSL_WANT_READ)
		{
			return;
		}

		if(res == 0)
		{
			g_log->error(m_name + ": Lost connection (2)");
			disconnect();
			ASSERT(false);
			return;
		}

		if(res != (int32_t) (header->len - sizeof(dragent_protocol_header)))
		{
			g_log->error(m_name + ": Protocol error (4): " + NumberFormatter::format(res));
			disconnect();
			ASSERT(false);
			return;
		}

		if(header->version != dragent_protocol::PROTOCOL_VERSION_NUMBER)
		{
			g_log->error(m_name + ": Received command for incompatible version protocol " 
				+ NumberFormatter::format(header->version));
			ASSERT(false);
			return;
		}

		g_log->information(m_name + ": Received command " 
			+ NumberFormatter::format(header->messagetype));

		switch(header->messagetype)
		{
			case draiosproto::message_type::DUMP_REQUEST:
				handle_dump_request(
					m_buffer.begin() + sizeof(dragent_protocol_header), 
					header->len - sizeof(dragent_protocol_header));
				break;
			case draiosproto::message_type::SSH_OPEN_CHANNEL:
				handle_ssh_open_channel(
					m_buffer.begin() + sizeof(dragent_protocol_header), 
					header->len - sizeof(dragent_protocol_header));
				break;
			case draiosproto::message_type::SSH_DATA:
				handle_ssh_data(
					m_buffer.begin() + sizeof(dragent_protocol_header), 
					header->len - sizeof(dragent_protocol_header));
				break;
			case draiosproto::message_type::SSH_CLOSE_CHANNEL:
				handle_ssh_close_channel(
					m_buffer.begin() + sizeof(dragent_protocol_header), 
					header->len - sizeof(dragent_protocol_header));
				break;
			case draiosproto::message_type::AUTO_UPDATE_REQUEST:
				handle_auto_update();
				break;
			default:
				g_log->error(m_name + ": Unknown message type: " 
					+ NumberFormatter::format(header->messagetype));
				ASSERT(false);
		}
	}
	catch(Poco::IOException& e)
	{
		g_log->error(m_name + ": " + e.displayText());
		disconnect();
	}
	catch(Poco::TimeoutException& e)
	{
	}
}

void connection_manager::handle_dump_request(uint8_t* buf, uint32_t size)
{
	draiosproto::dump_request request;
	if(!dragent_protocol::buffer_to_protobuf(buf, size, &request))
	{
		return;
	}

	string filter;
	if(request.has_filters())
	{
		filter = request.filters();
	}

	string token = request.token();

	SharedPtr<sinsp_worker::dump_job_request> job_request(
		new sinsp_worker::dump_job_request(token, request.duration_ns(), filter));
	
	m_sinsp_worker->schedule_dump_job(job_request);
}

void connection_manager::handle_ssh_open_channel(uint8_t* buf, uint32_t size)
{
	draiosproto::ssh_open_channel request;
	if(!dragent_protocol::buffer_to_protobuf(buf, size, &request))
	{
		return;
	}

	ssh_settings settings;

	if(request.has_user())
	{
		settings.m_user = request.user();
	}

	if(request.has_password())
	{
		settings.m_password = request.password();
	}

	if(request.has_key())
	{
		settings.m_key = request.key();
	}

	if(request.has_passphrase())
	{
		settings.m_passphrase = request.passphrase();
	}

	if(request.has_port())
	{
		settings.m_port = request.port();
	}

	ssh_worker* worker = new ssh_worker(m_configuration, m_queue, request.token(), settings);
	ThreadPool::defaultPool().start(*worker, "ssh_worker");
}

void connection_manager::handle_ssh_data(uint8_t* buf, uint32_t size)
{
	draiosproto::ssh_data request;
	if(!dragent_protocol::buffer_to_protobuf(buf, size, &request))
	{
		return;
	}

	if(request.has_data())
	{
		ssh_worker::request_input(request.token(), request.data());
	}
}

void connection_manager::handle_ssh_close_channel(uint8_t* buf, uint32_t size)
{
	draiosproto::ssh_close_channel request;
	if(!dragent_protocol::buffer_to_protobuf(buf, size, &request))
	{
		return;
	}

	ssh_worker::request_close(request.token());
}

void connection_manager::handle_auto_update()
{
	update_worker* worker = new update_worker(m_configuration);
	ThreadPool::defaultPool().start(*worker, "update_worker");
}
