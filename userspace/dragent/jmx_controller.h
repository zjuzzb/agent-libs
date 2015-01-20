#pragma once

#include "configuration.h"
#include "third-party/jsoncpp/json/json.h"

class jmx_controller : public Runnable
{
public:
	jmx_controller(dragent_configuration* configuration);

	void run();

	pair<FILE*, FILE*> get_io_fds();

private:
	// TODO: utility, can be moved outside if needed
	static void enable_nonblocking(int fd);

	enum pipe_dir
	{
		PIPE_READ = 0,
		PIPE_WRITE = 1
	};

	int m_inpipe[2];
	int m_outpipe[2];
	int m_errpipe[2];
	FILE *m_input_fd;
	FILE *m_output_fd;
	FILE *m_error_fd;
	Json::Reader m_json_reader;
	dragent_configuration *configuration;
	static const int READ_BUFFER_SIZE = 1024;
};