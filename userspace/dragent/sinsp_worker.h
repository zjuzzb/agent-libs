#pragma once

#include "main.h"
#include "configuration.h"
#include "sinsp_data_handler.h"

class captureinfo
{
public:
	captureinfo()
	{
		m_nevts = 0;
		m_time = 0;
	}

	uint64_t m_nevts;
	uint64_t m_time;
};

class sinsp_worker
{
public:
	sinsp_worker(dragent_configuration* configuration, dragent_queue* queue);
	~sinsp_worker();

	void init();
	captureinfo do_inspect();

private:
	dragent_configuration* m_configuration;
	sinsp* m_inspector;
	sinsp_analyzer* m_analyzer;
	sinsp_data_handler m_sinsp_handler;
};
