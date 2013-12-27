#pragma once

#include "main.h"
#include "protocol.h"
#include "connection_manager.h"

class dragent_sender : public Runnable
{
public:
	dragent_sender(dragent_queue* queue, connection_manager* connection_manager);

	void run();

private:
	bool transmit_buffer(const char* buffer, uint32_t buflen);

	static const string m_name;

	dragent_queue* m_queue;
	connection_manager* m_connection_manager;
};
