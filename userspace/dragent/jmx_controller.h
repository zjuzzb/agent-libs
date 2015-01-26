#pragma once

#include "configuration.h"
#include "third-party/jsoncpp/json/json.h"

class pipe_manager
{
public:
	explicit pipe_manager();
	~pipe_manager();

	// Get File descriptor to communicate with the child
	pair<FILE*, FILE*> get_io_fds()
	{
		make_pair(m_input_fd, m_output_fd);
	};

	FILE* get_err_fd()
	{
		return m_error_fd;
	}

	// Attach pipes to child STDIN, STDOUT and STDERR
	void attach_child_stdio();

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
};

class jmx_controller : public Runnable
{
public:
	jmx_controller(dragent_configuration* configuration, FILE* m_error_fd);

	void run();

private:
	FILE *m_error_fd;
	Json::Reader m_json_reader;
	dragent_configuration *configuration;
	static const int READ_BUFFER_SIZE = 1024;
};