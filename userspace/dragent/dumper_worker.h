#pragma once

#include "draios.pb.h"

#include "main.h"
#include "blocking_queue.h"
#include "configuration.h"
#include "protocol.h"
#include "connection_manager.h"

class dumper_worker : public Runnable
{
public:
	dumper_worker(dragent_queue* queue, dragent_configuration* configuration, uint64_t duration_ns):
		m_queue(queue),
		m_configuration(configuration),
		m_duration_ms(duration_ns / 1000000)
	{
	}

	void run()
	{
		g_log->information(m_name + ": Starting");

		g_log->information(m_name + ": Running for " + NumberFormatter::format(m_duration_ms) + " ms");
		dragent_configuration::m_dump_enabled = true;

		while(m_duration_ms && !dragent_configuration::m_terminate)
		{
			uint64_t sleep_time_ms;

			if(m_duration_ms > 1000)
			{
				sleep_time_ms = 1000;
			}
			else
			{
				sleep_time_ms = m_duration_ms;
			}

			Thread::sleep(sleep_time_ms);
			m_duration_ms -= sleep_time_ms;
		}

		if(!dragent_configuration::m_terminate)
		{
			dragent_configuration::m_dump_enabled = false;
			m_configuration->m_dump_completed.wait();

			g_log->information(m_name + ": Capture completed, sending file");

			send_file();
		}

		g_log->information(m_name + ": Terminating");

		delete this;
	}

	void send_file()
	{
		FileInputStream file(m_configuration->m_dump_file);
		string sfile;

		uint32_t nread = StreamCopier::copyToString(file, sfile);
		
		g_log->information(m_name + ": File size: " + NumberFormatter::format(nread));

		draiosproto::dump_response response;

		response.set_timestamp_ns(1234);
		response.set_customer_id(m_configuration->m_customer_id);
		response.set_machine_id(m_configuration->m_machine_id);
		response.set_content(sfile);

		SharedPtr<dragent_queue_item> buffer = dragent_protocol::message_to_buffer(dragent_protocol::PROTOCOL_MESSAGE_TYPE_DUMP_RESPONSE, response, m_configuration->m_compression_enabled);

		while(!m_queue->put(buffer) && !dragent_configuration::m_terminate)
		{
			g_log->error(m_name + ": Queue full, waiting");
			Thread::sleep(1000);
		}
	}

private:
	static const string m_name;

	dragent_queue* m_queue;
	dragent_configuration* m_configuration;
	uint64_t m_duration_ms;
};
