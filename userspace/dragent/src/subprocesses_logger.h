#pragma once

#include "configuration.h"
#include "watchdog_runnable.h"
#include "third-party/jsoncpp/json/json.h"
#include "error_handler.h"
#include "noncopyable.h"
#include <Poco/Message.h>

class watchdog_state;
class pipe_manager: noncopyable
{
public:
	pipe_manager();
	~pipe_manager();

	// Get File descriptor to communicate with the child
	std::pair<FILE*, FILE*> get_io_fds()
	{
		return std::make_pair(m_input_fd, m_output_fd);
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
	void operator()(const std::string&);
private:
	Json::Reader m_json_reader;
};

class cointerface_parser
{
public:
	void operator()(const std::string&);
private:
	Json::Reader m_json_reader;
};

class sinsp_logger_parser
{
public:
	sinsp_logger_parser(const std::string& procname, bool default_is_error=false);
	void operator()(const std::string&);
private:
	std::string m_prefix;
	bool m_default_is_error;
};

// Expects logs using sinsp_logger::OT_ENCODE_SEV
class sinsp_encoded_parser
{
public:
	sinsp_encoded_parser(const std::string& procname);
	void operator()(const std::string&);
private:
	std::string m_prefix;
};

class sdchecks_parser
{
public:
	sdchecks_parser();
	void operator()(const std::string&);
private:
	std::string m_last_pid_str;
	Poco::Message::Priority m_last_sev;
};

class subprocesses_logger : public dragent::watchdog_runnable
{
public:
	class log_state {
	public:
		log_state();
		log_state(std::function<void(const std::string&)> parser, watchdog_state *state);
		virtual ~log_state();
		std::function<void(const std::string&)> m_parser_f;
		std::shared_ptr<std::string> m_curbuf;
		watchdog_state *m_state;
	};

	subprocesses_logger(dragent_configuration* configuration, log_reporter* reporter);

	// `parser` is an rvalue reference because we expect a lambda
	// or a custom object created on the fly
	void add_logfd(FILE* fd, std::function<void(const std::string&)>&& parser, watchdog_state* state = nullptr);

	void do_run() override;

	static const unsigned READ_BUFFER_SIZE;
private:
	dragent_configuration *m_configuration;
	log_reporter* m_log_reporter;
	std::map<FILE *, log_state> m_error_fds;
};

