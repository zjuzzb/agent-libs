#pragma once

class dumper_worker : public Runnable
{
public:
	dumper_worker(blocking_queue* queue, dragent_configuration* configuration, uint64_t duration_ns):
		m_queue(queue),
		m_configuration(configuration),
		m_duration_ms(duration_ns / 1000000)
	{
	}

	void run()
	{
		g_log->information("Running dumper for " + NumberFormatter::format(m_duration_ms) + " ms");
		dragent_configuration::m_dump_enabled = true;
		Thread::sleep(m_duration_ms);
		dragent_configuration::m_dump_enabled = false;
		m_configuration->m_dump_completed.wait();
		g_log->information("Capture completed, sending file");
		send_file();
		delete this;
	}

	void send_file()
	{
		draiosproto::dump_response response;

		response.set_timestamp_ns(1234);
		response.set_customer_id(m_configuration->m_customer_id);
		response.set_machine_id(m_configuration->m_machine_id);
		response.set_content("THIS IS THE FILE CONTENT");
	}

private:
	blocking_queue* m_queue;
	dragent_configuration* m_configuration;
	uint64_t m_duration_ms;
};
