#pragma once

#include "main.h"
#include "protocol.h"
#include "configuration.h"
#include "draios.pb.h"

class sinsp_data_handler : public analyzer_callback_interface
{
public:
	sinsp_data_handler(dragent_queue* queue, dragent_configuration* configuration);

	void sinsp_analyzer_data_ready(uint64_t ts_ns, draiosproto::metrics* metrics);

private:
	dragent_queue* m_queue;
	dragent_configuration* m_configuration;
};
