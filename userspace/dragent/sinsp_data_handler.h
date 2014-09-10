#pragma once

#include "main.h"
#include "protocol.h"
#include "draios.pb.h"

class connection_manager;
class dragent_configuration;

class sinsp_data_handler : public analyzer_callback_interface
{
public:
	sinsp_data_handler(dragent_configuration* configuration, 
		connection_manager* connection_manager, protocol_queue* queue);

	void sinsp_analyzer_data_ready(uint64_t ts_ns, draiosproto::metrics* metrics);

private:
	dragent_configuration* m_configuration;
	connection_manager* m_connection_manager;
	protocol_queue* m_queue;
};
