#pragma once

#include "configuration.h"
#include "watchdog_runnable.h"
#include "third-party/jsoncpp/json/json.h"
#include "error_handler.h"

class watchdog_state;
class pipe_manager: noncopyable
{
public:
	pipe_manager();
	~pipe_manager();

	// Get File descriptor to communicate with the child
	pair<FILE*, FILE*> get_io_fds()
	{
		return make_pair(m_input_fd, m_output_fd);
	}

	FILE* get_err_fd()
	{
		return m_error_fd;
	}

	FILE* get_out_fd()
	{
		return m_output_fd;
	}

	// Attach pipes to child STDIN, STDOUT and STDERR
	void attach_child_stdio();
	int inpipe_size() const
	{
		return m_inpipe_size;
	}

	int outpipe_size() const
	{
		return m_outpipe_size;
	}

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
	FILE *m_input_fd = 0;
	FILE *m_output_fd = 0;
	FILE *m_error_fd = 0;
	int m_inpipe_size;
	int m_outpipe_size;
};

// A copy of the pipe_manager but that manages only stderr
class errpipe_manager: noncopyable
{
public:
	explicit errpipe_manager();
	~errpipe_manager();
	void attach_child();
	FILE* get_file()
	{
		return m_file;
	}

private:
	static void enable_nonblocking(int fd);
	enum pipe_dir
	{
		PIPE_READ = 0,
		PIPE_WRITE = 1
	};

	int m_pipe[2];
	FILE* m_file = 0;
};

class sdjagent_parser
{
public:
	void operator()(const string&);
private:
	Json::Reader m_json_reader;
};

class cointerface_parser
{
public:
	void operator()(const string&);
private:
	Json::Reader m_json_reader;
};

class sinsp_logger_parser
{
public:
	sinsp_logger_parser(const string& procname, bool default_is_error=false);
	void operator()(const string&);
private:
	string m_prefix;
	bool m_default_is_error;
};

class sdchecks_parser
{
public:
	sdchecks_parser();
	void operator()(const string&);
private:
	string m_last_pid_str;
	uint32_t m_last_sev;
};

class subprocesses_logger : public dragent::watchdog_runnable
{
public:
	subprocesses_logger(dragent_configuration* configuration, log_reporter* reporter);

	// `parser` is an rvalue reference because we expect a lambda
	// or a custom object created on the fly
	void add_logfd(FILE* fd, function<void(const string&)>&& parser, watchdog_state* state = nullptr);

	void do_run() override;

	static const unsigned READ_BUFFER_SIZE;
private:
	dragent_configuration *m_configuration;
	log_reporter* m_log_reporter;
	map<FILE *, pair<function<void(const string&)>, watchdog_state*>> m_error_fds;
};

