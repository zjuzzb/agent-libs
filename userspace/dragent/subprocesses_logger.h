#pragma once

#include "configuration.h"
#include "third-party/jsoncpp/json/json.h"
#include "error_handler.h"

class pipe_manager
{
public:
	explicit pipe_manager();
	~pipe_manager();

	// Get File descriptor to communicate with the child
	pair<FILE*, FILE*> get_io_fds()
	{
		return make_pair(m_input_fd, m_output_fd);
	};

	FILE* get_err_fd()
	{
		return m_error_fd;
	}

	// Attach pipes to child STDIN, STDOUT and STDERR
	void attach_child_stdio();

	pipe_manager(const pipe_manager&) = delete;
	pipe_manager& operator=(const pipe_manager&) = delete;
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

class sdjagent_parser
{
public:
	void operator()(const string&);
private:
	Json::Reader m_json_reader;
};

class subprocesses_logger : public Runnable
{
public:
	subprocesses_logger(dragent_configuration* configuration, log_reporter* reporter);

	// `parser` is an rvalue reference because we expect a lambda
	// or a custom object created on the fly
	void add_logfd(FILE* fd, function<void(const string&)>&& parser)
	{
		m_error_fds.emplace(fd, parser);
		auto fdno = fileno(fd);
		if (fdno > m_max_fd)
		{
			m_max_fd = fdno;
		}
		FD_SET(fdno, &m_readset);
	}

	void run();

	uint64_t get_last_loop_ns()
	{
		return m_last_loop_ns;
	}

	pthread_t get_pthread_id()
	{
		return m_pthread_id;
	}

private:
	dragent_configuration *m_configuration;
	log_reporter* m_log_reporter;
	map<FILE *, function<void(const string&)>> m_error_fds;
	struct timeval m_timeout;
	fd_set m_readset;
	int m_max_fd;
	volatile uint64_t m_last_loop_ns;
	volatile pthread_t m_pthread_id;
};

