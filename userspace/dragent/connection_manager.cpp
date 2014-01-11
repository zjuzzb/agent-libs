#include "connection_manager.h"

#include "logger.h"
#include "protocol.h"
#include "draios.pb.h"

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
			m_socket = new Poco::Net::SecureStreamSocket(*m_sa, m_configuration->m_server_addr);
			((Poco::Net::SecureStreamSocket*) m_socket.get())->verifyPeerCertificate();

			g_log->information("SSL identity verified");
		}
		else
		{
			m_socket = new Poco::Net::StreamSocket(*m_sa);
		}

		//
		// Set the send buffer size for the socket
		//
		m_socket->setSendBufferSize(m_configuration->m_transmitbuffer_size);
		m_socket->setSendTimeout(100000);
		m_socket->setReceiveTimeout(100000);

		g_log->information("Connected to collector");
		return true;
	}
	catch(Poco::IOException& e)
	{
		g_log->error(m_name + ": " + e.displayText());
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
			if(!connect())
			{
				Thread::sleep(1000);
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

		g_log->information(m_name + ": Sent " 
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
			case dragent_protocol::PROTOCOL_MESSAGE_TYPE_DUMP_REQUEST:
				handle_dump_request(
					m_buffer.begin() + sizeof(dragent_protocol_header), 
					header->len - sizeof(dragent_protocol_header));
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
	google::protobuf::io::ArrayInputStream stream(buf, size);
	google::protobuf::io::GzipInputStream gzstream(&stream);

	draiosproto::dump_request request;
	bool res = request.ParseFromZeroCopyStream(&gzstream);
	if(!res)
	{
		g_log->error(m_name + ": Error reading request");
		ASSERT(false);
		return;
	}

	string filter;
	if(request.has_filters())
	{
		filter = request.filters();
	}

	SharedPtr<sinsp_worker::dump_job_request> job_request(
		new sinsp_worker::dump_job_request(request.duration_ns(), filter));
	
	m_sinsp_worker->schedule_dump_job(job_request);
}
