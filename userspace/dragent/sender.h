#pragma once

#include "main.h"
#include "protocol.h"
#include "connection_manager.h"

class dragent_sender : public Runnable
{
public:
	dragent_sender(dragent_queue* queue, connection_manager* connection_manager):
		m_queue(queue),
		m_connection_manager(connection_manager)
	{
	}

	void run()
	{
		g_log->information(m_name + ": Starting");

		while(!dragent_configuration::m_terminate)
		{
			SharedPtr<dragent_queue_item> item;

			try
			{
				item = m_queue->get();
			}
			catch(Poco::TimeoutException& e)
			{
				continue;
			}

			while(!transmit_buffer(item->data(), item->size()))
			{
				if(dragent_configuration::m_terminate)
				{
					break;
				}

				Thread::sleep(1000);
			}
		}

		g_log->information(m_name + ": Terminating");
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

		SharedPtr<StreamSocket> socket = m_connection_manager->get_socket();
		if(socket.isNull())
		{
			return false;
		}

		try
		{
			int32_t res = socket->sendBytes(buffer, buflen);
			if(res != (int32_t) buflen)
			{
				g_log->error(m_name + ": sendBytes sent just " 
					+ NumberFormatter::format(res) 
					+ ", expected " + NumberFormatter::format(buflen));	
				ASSERT(false);
				m_connection_manager->close();
				return false;
			}

			g_log->information(m_name + ": Sent " 
				+ Poco::NumberFormatter::format(buflen) + " to collector");

			return true;
		}
		catch(Poco::IOException& e)
		{
			//
			// Disconnected from backend, let the receiver thread reconnect
			//
			g_log->error(m_name + ": " + e.displayText());
		}
		catch(Poco::TimeoutException& e)
		{
			//
			// Timeout during send, needed to check if the thread must terminate
			//
		}

		return false;
	}

private:
	static const string m_name;

	dragent_queue* m_queue;
	connection_manager* m_connection_manager;
};
