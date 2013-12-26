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
		m_stop(false),
		m_queue(queue),
		m_configuration(configuration),
		m_connection_manager(connection_manager)
	{
	}

	void run()
	{
		g_log->information(m_name + ": Starting");

		while(!m_stop)
		{
			uint32_t size;

			try
			{
				StreamSocket* socket = m_connection_manager->get_socket();

				if(socket != NULL)
				{
					int32_t res = socket->receiveBytes(&size, sizeof(size), MSG_WAITALL);
					ASSERT(res == (int32_t) sizeof(size));

					size = ntohl(size);

					ASSERT(size > sizeof(size));
					ASSERT(size <= RECEIVER_BUFSIZE);
					ASSERT(size >= sizeof(size) + 2);

					size -= sizeof(size);

					res = socket->receiveBytes(m_buf, size, MSG_WAITALL);
					ASSERT(res == (int32_t) size);

					if(m_buf[0] != dragent_protocol::PROTOCOL_VERSION_NUMBER)
					{
						g_log->error(m_name + ": Received command for incompatible version protocol " + NumberFormatter::format(m_buf[0]));
					}

					g_log->information(m_name + ": Received command " + NumberFormatter::format(m_buf[1]));

					switch(m_buf[1])
					{
						case dragent_protocol::PROTOCOL_MESSAGE_TYPE_DUMP_REQUEST:
							ASSERT(size > 2);
							size -= 2;
							handle_dump_request(&m_buf[2], size);
							break;
						default:
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

	bool m_stop;

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

	static const uint32_t RECEIVER_BUFSIZE = 1024;
	static const string m_name;

	uint8_t m_buf[RECEIVER_BUFSIZE];
	dragent_queue* m_queue;
	dragent_configuration* m_configuration;
	connection_manager* m_connection_manager;
};
