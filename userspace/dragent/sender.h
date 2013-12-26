#pragma once

#include "main.h"
#include "protocol.h"

class dragent_sender : public Runnable
{
public:
	dragent_sender(dragent_queue* queue, connection_manager* connection_manager):
		m_stop(false),
		m_queue(queue),
		m_connection_manager(connection_manager)
	{
	}

	void run()
	{
		while(!m_stop)
		{
			SharedPtr<dragent_queue_item> item = m_queue->get();

			while(!m_stop)
			{
				if(transmit_buffer(item->data(), item->size()))
				{
					break;
				}

				Thread::sleep(1000);
			}
		}
	}

	bool transmit_buffer(const char* buffer, uint32_t buflen)
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

		StreamSocket* socket = NULL;

		try
		{
			socket = m_connection_manager->get_socket();

			if(socket == NULL)
			{
				g_log->information("Connecting to collector...");
				m_connection_manager->connect();
				socket = m_connection_manager->get_socket();
			}

			int32_t res = socket->sendBytes(buffer, buflen);
			ASSERT(res == (int32_t) buflen);

			g_log->information("Sent " + Poco::NumberFormatter::format(buflen) + " to collector");

			return true;
		}
		catch(Poco::IOException& e)
		{
			g_log->error(e.displayText());
			
			if(socket != NULL)
			{
				g_log->error("Sender thread lost connection");
				m_connection_manager->close();
			}
		}

		return false;
	}

	Thread m_thread;
	bool m_stop;

private:
	dragent_queue* m_queue;
	connection_manager* m_connection_manager;
};
