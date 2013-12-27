#include "receiver.h"

const string dragent_receiver::m_name = "receiver";

dragent_receiver::dragent_receiver(dragent_queue* queue, dragent_configuration* configuration, connection_manager* connection_manager):
	m_buffer(RECEIVER_BUFSIZE),
	m_queue(queue),
	m_configuration(configuration),
	m_connection_manager(connection_manager)
{
}

void dragent_receiver::run()
{
	g_log->information(m_name + ": Starting");

	while(!dragent_configuration::m_terminate)
	{
		SharedPtr<StreamSocket> socket = m_connection_manager->get_socket();

		try
		{
			if(socket.isNull())
			{
				m_connection_manager->connect();
				socket = m_connection_manager->get_socket();
				continue;
			}

			int32_t res = socket->receiveBytes(m_buffer.begin(), sizeof(dragent_protocol_header), MSG_WAITALL);
			if(res == 0)
			{
				g_log->error(m_name + ": Lost connection (1)");
				m_connection_manager->close();
				continue;
			}

			if(res != sizeof(dragent_protocol_header))
			{
				g_log->error(m_name + ": Protocol error (1): " + NumberFormatter::format(res));
				ASSERT(false);
				m_connection_manager->close();
				continue;
			}

			dragent_protocol_header* header = (dragent_protocol_header*) m_buffer.begin();
			header->len = ntohl(header->len);

			if(header->len > RECEIVER_BUFSIZE)
			{
				g_log->error(m_name + ": Protocol error (2): " + NumberFormatter::format(header->len));
				ASSERT(false);
				m_connection_manager->close();
				continue;						
			}

			if(header->len < sizeof(dragent_protocol_header))
			{
				g_log->error(m_name + ": Protocol error (3): " + NumberFormatter::format(header->len));
				ASSERT(false);
				m_connection_manager->close();
				continue;					
			}

			res = socket->receiveBytes(
				m_buffer.begin() + sizeof(dragent_protocol_header), 
				header->len - sizeof(dragent_protocol_header), 
				MSG_WAITALL);

			if(res == 0)
			{
				g_log->error(m_name + ": Lost connection (2)");
				m_connection_manager->close();
				continue;
			}

			if(res != (int32_t) (header->len - sizeof(dragent_protocol_header)))
			{
				g_log->error(m_name + ": Protocol error (4): " + NumberFormatter::format(res));
				ASSERT(false);
				continue;											
			}

			if(header->version != dragent_protocol::PROTOCOL_VERSION_NUMBER)
			{
				g_log->error(m_name + ": Received command for incompatible version protocol " 
					+ NumberFormatter::format(header->version));
				ASSERT(false);
				continue;
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
			g_log->error(m_name + ": Lost connection (3)");
			m_connection_manager->close();
			Thread::sleep(1000);
		}
		catch(Poco::TimeoutException& e)
		{
		}
	}

	g_log->information(m_name + ": Terminating");
}

void dragent_receiver::handle_dump_request(uint8_t* buf, uint32_t size)
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

	uint64_t duration_ns = request.duration_ns();

	dumper_worker* worker = new dumper_worker(m_queue, m_configuration, duration_ns);
	ThreadPool::defaultPool().start(*worker, "dumper_worker");
}
