#pragma once

class dragent_sender : public Runnable
{
public:
	dragent_sender(blocking_queue* queue, connection_manager* connection_manager):
		m_stop(false),
		m_queue(queue),
		m_connection_manager(connection_manager)
	{
	}

	void run()
	{
		while (!m_stop)
		{
			blocking_queue::item* item = m_queue->get();
			printf("received %p!\n", item);
			transmit_buffer(item->m_buf, item->m_len);
			delete item;
		}
	}

	void transmit_buffer(char* buffer, uint32_t buflen)
	{
		//
		// Do a fake read to make sure openssl reads the stream from
		// the server and detects any pending alerts
		//
		// try 
		// {
		// 	char buf;
		// 	m_connection_manager.get_socket()->receiveBytes(&buf, 1);
		// }
		// catch(Poco::TimeoutException&)
		// {
		// 	//
		// 	// Poco signals a NONBLOCKING read that would block with
		// 	// an exception
		// 	//
		// }

		// if(g_ssl_alert_received)
		// {
		// 	throw sinsp_exception("Received SSL alert, terminating the connection");
		// }

		int32_t res = m_connection_manager->get_socket()->sendBytes(buffer, buflen);
		ASSERT(res == (int32_t) buflen);
	}

	Thread m_thread;
	bool m_stop;

private:
	blocking_queue *m_queue;
	connection_manager* m_connection_manager;
};
