#include "connection_manager.h"

#include "logger.h"
#include "protocol.h"
#include "draios.pb.h"
#include "ssh_worker.h"
#include "update_worker.h"
#include "utils.h"

#ifndef TCP_USER_TIMEOUT
// Define it here because old glibc versions do not have this flag (eg, Centos6)
#define TCP_USER_TIMEOUT	 18 /* How long for loss retry before timeout */
#endif

const string connection_manager::m_name = "connection_manager";
const chrono::seconds connection_manager::WORKING_INTERVAL_S(10);
const uint32_t connection_manager::RECONNECT_MIN_INTERVAL_S = 1;
const uint32_t connection_manager::RECONNECT_MAX_INTERVAL_S = 60;

connection_manager::connection_manager(dragent_configuration* configuration, 
		protocol_queue* queue, sinsp_worker* sinsp_worker):
	m_socket(NULL),
	m_connected(false),
	m_buffer(RECEIVER_BUFSIZE),
	m_buffer_used(0),
	m_configuration(configuration),
	m_queue(queue),
	m_sinsp_worker(sinsp_worker),
	m_last_loop_ns(0),
	m_reconnect_interval(0)
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
		if(m_configuration->m_ssl_enabled)
		{
			g_log->information("SSL enabled, initializing context");

			Poco::Net::Context::VerificationMode verification_mode;

			if(m_configuration->m_ssl_verify_certificate)
			{
				verification_mode = Poco::Net::Context::VERIFY_STRICT;
			}
			else
			{
				verification_mode = Poco::Net::Context::VERIFY_NONE;
			}

			Poco::Net::Context::Ptr ptrContext = new Poco::Net::Context(
				Poco::Net::Context::CLIENT_USE, 
				"", 
				"", 
				m_configuration->m_ssl_ca_certificate, 
				verification_mode,
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

		SocketAddress sa(m_configuration->m_server_addr, m_configuration->m_server_port);

		g_log->information("Connecting to collector " + sa.toString());

		if(m_configuration->m_ssl_enabled)
		{
			m_socket = new Poco::Net::SecureStreamSocket();

			((Poco::Net::SecureStreamSocket*) m_socket.get())->setLazyHandshake(true);
			((Poco::Net::SecureStreamSocket*) m_socket.get())->setPeerHostName(m_configuration->m_server_addr);
			((Poco::Net::SecureStreamSocket*) m_socket.get())->connect(sa, SOCKET_TIMEOUT_DURING_CONNECT_US);
		}
		else
		{
			m_socket = new Poco::Net::StreamSocket();
			m_socket->connect(sa, SOCKET_TIMEOUT_DURING_CONNECT_US);
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
		try
		{
			// This option makes the connection fail earlier in case of unplugged cable
			m_socket->setOption(IPPROTO_TCP, TCP_USER_TIMEOUT, SOCKET_TCP_TIMEOUT_MS);
		}
		catch(std::exception&)
		{
			// ignore if kernel does not support this
			// alternatively, could be a setsockopt() call to avoid exception
		}

		g_log->information("Connected to collector");
		m_connected = true;
		return true;
	}
	catch(Poco::IOException& e)
	{
		g_log->error(m_name + ": " + e.displayText());
		disconnect();
		return false;
	}
	catch(Poco::TimeoutException& e)
	{
		g_log->error(m_name + ": " + e.displayText());
		disconnect();
		return false;
	}
	return false;
}

void connection_manager::disconnect()
{
	if(chrono::system_clock::now() - m_last_connection_failure >= WORKING_INTERVAL_S)
	{
		m_reconnect_interval = RECONNECT_MIN_INTERVAL_S;
	}
	else
	{
		m_reconnect_interval = std::min(std::max(connection_manager::RECONNECT_MIN_INTERVAL_S, m_reconnect_interval * 2), RECONNECT_MAX_INTERVAL_S);
	}

	if(!m_socket.isNull())
	{
		m_socket->close();
		m_socket = NULL;
		m_connected = false;
		m_buffer_used = 0;
	}
}

void connection_manager::run()
{
	m_pthread_id = pthread_self();

	g_log->information(m_name + ": Starting");

	if(init())
	{
		SharedPtr<protocol_queue_item> item;

		while(!dragent_configuration::m_terminate)
		{
			m_last_loop_ns = sinsp_utils::get_current_time_ns();

			//
			// Make sure we have a valid connection
			//
			if(m_socket.isNull())
			{
				g_log->information(string("Waiting to connect ") + std::to_string(m_reconnect_interval) + " s");
				for(uint32_t waited_time = 0; waited_time < m_reconnect_interval && !dragent_configuration::m_terminate; ++waited_time)
				{
					m_last_loop_ns = sinsp_utils::get_current_time_ns();
					Thread::sleep(1000);
				}

				if(dragent_configuration::m_terminate)
				{
					break;
				}
				
				m_last_connection_failure = chrono::system_clock::now();

				if(!connect())
				{
					continue;
				}
			}

			//
			// Check if we received a message. We do it before so nothing gets lost if ELBs
			// still negotiates a connection and then sends us out at the first read/write
			//
			receive_message();

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
		}
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
		if(res == Poco::Net::SecureStreamSocket::ERR_SSL_WANT_READ ||
			res == Poco::Net::SecureStreamSocket::ERR_SSL_WANT_WRITE)
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

		if(m_buffer_used == 0)
		{
			// We begin by reading and processing the protocol header
			int32_t res = m_socket->receiveBytes(m_buffer.begin(), sizeof(dragent_protocol_header), MSG_WAITALL);
			if(res == Poco::Net::SecureStreamSocket::ERR_SSL_WANT_READ ||
			   res == Poco::Net::SecureStreamSocket::ERR_SSL_WANT_WRITE)
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

			if(header->len < sizeof(dragent_protocol_header))
			{
				g_log->error(m_name + ": Protocol error (3): " + NumberFormatter::format(header->len));
				ASSERT(false);
				disconnect();
				return;
			}

			if(header->len > m_buffer.size())
			{
				m_buffer.resize(header->len);
			}

			m_buffer_used = sizeof(dragent_protocol_header);
		}

		// Then we read the actual message, it may arrive in
		// several chunks, in this case the function will be called
		// at the next loop cycle and will continue reading
		auto header = (dragent_protocol_header*) m_buffer.begin();
		auto res = m_socket->receiveBytes(
				m_buffer.begin() + m_buffer_used,
				header->len - m_buffer_used,
				MSG_WAITALL);

		if(res == Poco::Net::SecureStreamSocket::ERR_SSL_WANT_READ ||
			res == Poco::Net::SecureStreamSocket::ERR_SSL_WANT_WRITE)
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

		if(res < 0)
		{
			g_log->error(m_name + ": Connection error: " + NumberFormatter::format(res));
			disconnect();
			ASSERT(false);
			return;
		}

		m_buffer_used += res;

		if(m_buffer_used == header->len)
		{
			m_buffer_used = 0;

			if(header->version != dragent_protocol::PROTOCOL_VERSION_NUMBER)
			{
				g_log->error(m_name + ": Received command for incompatible version protocol "
							 + NumberFormatter::format(header->version));
				ASSERT(false);
				return;
			}

			// When the message is complete, process it
			// and reset the buffer
			g_log->information(m_name + ": Received command "
							   + NumberFormatter::format(header->messagetype)
							   + " (" + draiosproto::message_type_Name((draiosproto::message_type) header->messagetype) + ")");

			switch(header->messagetype)
			{
			case draiosproto::message_type::DUMP_REQUEST_START:
				handle_dump_request_start(
						m_buffer.begin() + sizeof(dragent_protocol_header),
						header->len - sizeof(dragent_protocol_header));
				break;
			case draiosproto::message_type::DUMP_REQUEST_STOP:
				handle_dump_request_stop(
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
			case draiosproto::message_type::CONFIG_DATA:
				handle_config_data(
						m_buffer.begin() + sizeof(dragent_protocol_header),
						header->len - sizeof(dragent_protocol_header));
				break;
			default:
				g_log->error(m_name + ": Unknown message type: "
							 + NumberFormatter::format(header->messagetype));
				ASSERT(false);
			}
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

void connection_manager::handle_dump_request_start(uint8_t* buf, uint32_t size)
{
	draiosproto::dump_request_start request;
	if(!dragent_protocol::buffer_to_protobuf(buf, size, &request))
	{
		return;
	}

	SharedPtr<sinsp_worker::dump_job_request> job_request(
		new sinsp_worker::dump_job_request());

	job_request->m_request_type = sinsp_worker::dump_job_request::JOB_START;
	job_request->m_token = request.token();
	
	if(request.has_filters())
	{
		job_request->m_filter = request.filters();
	}

	if(request.has_duration_ns())
	{
		job_request->m_duration_ns = request.duration_ns();
	}

	if(request.has_max_size())
	{
		job_request->m_max_size = request.max_size();
	}
	
	m_sinsp_worker->queue_job_request(job_request);
}

void connection_manager::handle_dump_request_stop(uint8_t* buf, uint32_t size)
{
	draiosproto::dump_request_stop request;
	if(!dragent_protocol::buffer_to_protobuf(buf, size, &request))
	{
		return;
	}

	SharedPtr<sinsp_worker::dump_job_request> job_request(
		new sinsp_worker::dump_job_request());

	job_request->m_request_type = sinsp_worker::dump_job_request::JOB_STOP;
	job_request->m_token = request.token();

	m_sinsp_worker->queue_job_request(job_request);
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

void connection_manager::handle_config_data(uint8_t* buf, uint32_t size)
{
	if(m_configuration->m_auto_config)
	{
		draiosproto::config_data request;
		if(!dragent_protocol::buffer_to_protobuf(buf, size, &request))
		{
			return;
		}
		for(const auto& config_file_proto : request.config_files())
		{
			if(config_file_proto.name() == "dragent.auto.yaml")
			{
				m_configuration->save_auto_config(config_file_proto.content());
				break;
			}
		}
	}
	else
	{
		g_log->debug("Auto config disabled, ignoring CONFIG_DATA message");
	}
}