#pragma once

#include <google/protobuf/io/gzip_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>

#include "draios.pb.h"
#include "dumper_worker.h"
#include "protocol.h"

class dragent_receiver : public Runnable
{
public:
	dragent_receiver(dragent_queue* queue, dragent_configuration* configuration, connection_manager* connection_manager):
		m_buffer(RECEIVER_BUFSIZE),
		m_queue(queue),
		m_configuration(configuration),
		m_connection_manager(connection_manager)
	{
	}

	void run()
	{
		g_log->information(m_name + ": Starting");

		while(!dragent_configuration::m_terminate)
		{
			try
			{
				StreamSocket* socket = m_connection_manager->get_socket();

				if(socket != NULL)
				{
					int32_t res = socket->receiveBytes(m_buffer.begin(), sizeof(dragent_protocol_header), MSG_WAITALL);
					if(res == 0)
					{
						continue;
					}

					if(res != sizeof(dragent_protocol_header))
					{
						g_log->error(m_name + ": Protocol error (1): " + NumberFormatter::format(res));
						ASSERT(false);
						continue;
					}

					dragent_protocol_header* header = (dragent_protocol_header*) m_buffer.begin();
					header->len = ntohl(header->len);

					if(header->len > RECEIVER_BUFSIZE)
					{
						g_log->error(m_name + ": Protocol error (2): " + NumberFormatter::format(header->len));
						ASSERT(false);
						continue;						
					}

					if(header->len < sizeof(dragent_protocol_header))
					{
						g_log->error(m_name + ": Protocol error (3): " + NumberFormatter::format(header->len));
						ASSERT(false);
						continue;					
					}

					res = socket->receiveBytes(
						m_buffer.begin() + sizeof(dragent_protocol_header), 
						header->len - sizeof(dragent_protocol_header), 
						MSG_WAITALL);

					if(res == 0)
					{
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
				else
				{
					Thread::sleep(1000);
				}
			}
			catch(Poco::IOException& e)
			{
				g_log->error(e.displayText());
				g_log->error(m_name + ": Receiver thread lost connection");
			}
			catch(Poco::TimeoutException& e)
			{
			}
		}

		g_log->information(m_name + ": Terminating");
	}

private:
	void handle_dump_request(uint8_t* buf, uint32_t size)
	{
		google::protobuf::io::ArrayInputStream stream(buf, size);
		google::protobuf::io::GzipInputStream gzstream(&stream);

		draiosproto::dump_request request;
		bool res = request.ParseFromZeroCopyStream(&gzstream);
		ASSERT(res);

		uint64_t duration_ns = request.duration_ns();

		dumper_worker* worker = new dumper_worker(m_queue, m_configuration, duration_ns);
		ThreadPool::defaultPool().start(*worker, "dumper_worker");
	}

	static const uint32_t RECEIVER_BUFSIZE = 32 * 1024;
	static const string m_name;

	Buffer<uint8_t> m_buffer;
	dragent_queue* m_queue;
	dragent_configuration* m_configuration;
	connection_manager* m_connection_manager;
};
