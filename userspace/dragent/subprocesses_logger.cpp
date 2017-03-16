#include "subprocesses_logger.h"
#include "logger.h"
#include "utils.h"
#include "dragent.h"

// On systems with kernel < 2.6.35 we don't have this flag
// so define it and compile our code anyway as we need it when
// running on most recent kernels
#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ 1031
#endif

pipe_manager::pipe_manager()
{
	// Create pipes
	int ret = pipe(m_inpipe);
	if(ret != 0)
	{
		// We don't have logging enabled when this constructor is called
		cerr << "Cannot create pipe()" << endl;
	}
	ret = pipe(m_outpipe);
	if(ret != 0)
	{
		cerr << "Cannot create pipe()" << endl;
	}
	ret = pipe(m_errpipe);
	if(ret != 0)
	{
		cerr << "Cannot create pipe()" << endl;
	}

	// transform to FILE*
	m_input_fd = fdopen(m_inpipe[PIPE_WRITE], "w");
	m_output_fd = fdopen(m_outpipe[PIPE_READ], "r");
	m_error_fd = fdopen(m_errpipe[PIPE_READ], "r");

	// Use non blocking io
	enable_nonblocking(m_outpipe[PIPE_READ]);
	enable_nonblocking(m_errpipe[PIPE_READ]);
	enable_nonblocking(m_inpipe[PIPE_WRITE]);

	// We need bigger buffers on pipes, for example for JMX data
	m_inpipe_size = fcntl(m_inpipe[PIPE_READ], F_SETPIPE_SZ, PIPE_BUFFER_SIZE);
	m_outpipe_size = fcntl(m_outpipe[PIPE_WRITE], F_SETPIPE_SZ, PIPE_BUFFER_SIZE);
}

pipe_manager::~pipe_manager()
{
	close(m_inpipe[PIPE_READ]);
	if(m_input_fd) { fclose(m_input_fd); }
	close(m_outpipe[PIPE_WRITE]);
	if(m_output_fd) { fclose(m_output_fd); }
	close(m_errpipe[PIPE_WRITE]);
	if(m_error_fd) { fclose(m_error_fd); }
}

void pipe_manager::attach_child_stdio()
{
	dup2(m_outpipe[PIPE_WRITE], STDOUT_FILENO);
	dup2(m_errpipe[PIPE_WRITE], STDERR_FILENO);
	dup2(m_inpipe[PIPE_READ], STDIN_FILENO);
	// Close the other part of the pipes
	fclose(m_input_fd); m_input_fd = 0;
	fclose(m_output_fd); m_output_fd = 0;
	fclose(m_error_fd); m_error_fd = 0;
}

void pipe_manager::enable_nonblocking(int fd)
{
	int flags;
	flags = fcntl(fd, F_GETFL, 0);
	flags |= O_NONBLOCK;
	fcntl(fd, F_SETFL, flags);
}

errpipe_manager::errpipe_manager()
{
	// Create pipes
	int ret = pipe(m_pipe);
	if(ret != 0)
	{
		// We don't have logging enabled when this constructor is called
		cerr << "Cannot create pipe()" << endl;
	}

	// transform to FILE*
	m_file = fdopen(m_pipe[PIPE_READ], "r");

	// Use non blocking io
	enable_nonblocking(m_pipe[PIPE_READ]);
}

errpipe_manager::~errpipe_manager()
{
	close(m_pipe[PIPE_WRITE]);
	if(m_file)
	{
		fclose(m_file);
	}
}

void errpipe_manager::attach_child()
{
	dup2(m_pipe[PIPE_WRITE], STDERR_FILENO);
	// Close the other part of the pipes
	fclose(m_file);
	m_file = 0;
}

void errpipe_manager::enable_nonblocking(int fd)
{
	int flags;
	flags = fcntl(fd, F_GETFL, 0);
	flags |= O_NONBLOCK;
	fcntl(fd, F_SETFL, flags);
}

void sdjagent_parser::operator()(const string& data)
{
	// Parse log level and use it
	Json::Value sdjagent_log;
	bool parsing_ok = m_json_reader.parse(data, sdjagent_log, false);
	if(parsing_ok && sdjagent_log.isObject())
	{
		unsigned pid = sdjagent_log["pid"].asUInt();
		string log_level = sdjagent_log["level"].asString();
		string log_message = "sdjagent[" + to_string(pid) + "]: " + sdjagent_log["message"].asString();
		if(log_level == "SEVERE")
		{
			g_log->error(log_message);
		}
		else if(log_level == "WARNING")
		{
			g_log->warning(log_message);
		}
		else if(log_level == "INFO")
		{
			g_log->information(log_message);
		}
		else
		{
			g_log->debug(log_message);
		}
	}
	else
	{
		g_log->error("sdjagent, " + data);
	}
}

void cointerface_parser::operator()(const string& data)
{
	// Parse log level and use it
	Json::Value cointerface_log;
	bool parsing_ok = m_json_reader.parse(data, cointerface_log, false);
	if(parsing_ok && cointerface_log.isObject())
	{
		unsigned pid = cointerface_log["pid"].asUInt();
		string log_level = cointerface_log["level"].asString();
		string log_message = "cointerface[" + to_string(pid) + "]: " + cointerface_log["message"].asString();
		if(log_level == "Trace")
		{
			g_log->trace(log_message);
		} else if(log_level == "Debug")
		{
			g_log->debug(log_message);
		} else if(log_level == "Info")
		{
			g_log->information(log_message);
		} else if(log_level == "Warn")
		{
			g_log->warning(log_message);
		} else if(log_level == "Error")
		{
			g_log->error(log_message);
		} else if(log_level == "Critical")
		{
			g_log->critical(log_message);
		} else {
			// Shouldn't happen, but just in case
			assert(false);
			g_log->critical("Unparsable log level: " + log_message);
		}
	}
	else
	{
		assert(false);
		g_log->critical("Cointerface, unparsable log message: " + data);
	}
}

sinsp_logger_parser::sinsp_logger_parser(const string& procname):
	m_prefix(procname + ": ")
{

}

void sinsp_logger_parser::operator()(const string& s)
{
	// Right now we are using default sinsp stderror logger
	// it does not send priority so we are using a simple heuristic
	if(s.find("Error") != string::npos)
	{
		g_log->error(m_prefix + s);
	}
	else if(s.find("Warning") != string::npos)
	{
		g_log->warning(m_prefix +s);
	}
	else if(s.find("Info") != string::npos)
	{
		g_log->information(m_prefix +s);
	}
	else
	{
		g_log->debug(m_prefix + s);
	}
}

subprocesses_logger::subprocesses_logger(dragent_configuration *configuration, log_reporter* reporter) :
		m_configuration(configuration),
		m_log_reporter(reporter),
		m_last_loop_ns(0)
{
}

void subprocesses_logger::add_logfd(FILE *fd, function<void(const string&)> &&parser, watchdog_state* state)
{
	m_error_fds.emplace(fd, make_pair(parser, state));
}

void subprocesses_logger::run()
{
	m_pthread_id = pthread_self();
	g_log->information("subprocesses_logger: Starting");

	if(m_error_fds.empty())
	{
		g_log->information("subprocesses_logger: no log fds, closing");
		return;
	}

	while(!dragent_configuration::m_terminate)
	{
		m_last_loop_ns = sinsp_utils::get_current_time_ns();

		int max_fd = 0;
		fd_set readset_w;
		FD_ZERO(&readset_w);
		for(const auto& fds : m_error_fds)
		{
			auto fd = fileno(fds.first);
			FD_SET(fd, &readset_w);
			max_fd = std::max(fd, max_fd);
		}
		struct timeval timeout_w = { 0 };
		timeout_w.tv_sec = 1;

		int result = select(max_fd+1, &readset_w, NULL, NULL, &timeout_w);

		if(result > 0 )
		{
			for(const auto& fds : m_error_fds)
			{
				if(FD_ISSET(fileno(fds.first), &readset_w))
				{
					auto available_stream = fds.first;
					static const auto READ_BUFFER_SIZE = 1024;
					char buffer[READ_BUFFER_SIZE];
					auto fgets_res = fgets_unlocked(buffer, READ_BUFFER_SIZE, available_stream);
					while(fgets_res != NULL)
					{
						string data(buffer);
						trim(data);
						if(fds.second.second != nullptr && data.find("HB,") == 0)
						{
							// This is an heartbeat message, so parse and store values
							// for watchdog, format: HB,pid,memory_used,last_loop_ts
							StringTokenizer tokenizer(data, ",");
							if(tokenizer.count() > 3)
							{
								fds.second.second->reset(stoul(tokenizer[1]),
														 stoul(tokenizer[2]),
														 stoul(tokenizer[3]));
							}
							g_log->debug("Received heartbeat: " + data);
						}
						else
						{
							fds.second.first(data);
						}
						fgets_res = fgets_unlocked(buffer, READ_BUFFER_SIZE, available_stream);
					}
				}
			}
		}
		if(dragent_configuration::m_send_log_report)
		{
			m_log_reporter->send_report();
			dragent_configuration::m_send_log_report = false;
		}
	}
	g_log->information("subprocesses_logger terminating");
}
