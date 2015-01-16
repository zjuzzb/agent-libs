#pragma once

#include "configuration.h"

class jmx_controller : public Runnable
{
public:
	jmx_controller(dragent_configuration* configuration);

	void run();

	pair<int, int> get_io_fds();

private:
	enum pipe_dir
	{
		PIPE_READ = 0,
		PIPE_WRITE = 1
	};
	int m_inpipe[2];
	int m_outpipe[2];
	int m_errpipe[2];
	dragent_configuration *configuration;
};