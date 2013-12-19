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
			m_connection_manager->get_socket()->receiveBytes(&size, sizeof(size), MSG_WAITALL);
			printf("\nhaha\n");
		}
	}

	Thread m_thread;
	bool m_stop;

private:
	blocking_queue *m_queue;
	connection_manager* m_connection_manager;
};
