#pragma once

class dragent_receiver : public Runnable
{
public:
	dragent_receiver(blocking_queue* queue, connection_manager* connection_manager):
		m_stop(false),
		m_queue(queue),
		m_connection_manager(connection_manager)
	{
	}

	void run()
	{
		while (!m_stop)
		{
			uint32_t size;

			try
			{
				// m_connection_manager->get_socket()->receiveBytes(&size, sizeof(size), MSG_WAITALL);
			}
			catch(Poco::IOException& e)
			{
				g_log->error(e.displayText());
				g_log->error("Receiver thread lost connection");
			}
		}
	}

	Thread m_thread;
	bool m_stop;

private:
	blocking_queue *m_queue;
	connection_manager* m_connection_manager;
};
