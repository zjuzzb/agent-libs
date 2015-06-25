#include "subprocesses_logger.h"
#include "logger.h"
#include "utils.h"

// On systems with kernel < 2.6.35 we don't have this flag
// so define it and compile our code anyway as we need it when
// running on most recent kernels
#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ	(F_LINUX_SPECIFIC_BASE + 7)
#endif

pipe_manager::pipe_manager()
{
	static const int PIPE_BUFFER_SIZE = 1048576;

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
	ret = fcntl(m_inpipe[PIPE_READ], F_SETPIPE_SZ, PIPE_BUFFER_SIZE);
	if (ret < 0)
	{
		cerr << "Cannot increase pipe size" << endl;
	}
	ret = fcntl(m_outpipe[PIPE_WRITE], F_SETPIPE_SZ, PIPE_BUFFER_SIZE);
	if (ret < 0)
	{
		cerr << "Cannot increase pipe size" << endl;
	}
}

pipe_manager::~pipe_manager()
{
	close(m_inpipe[PIPE_READ]);
	fclose(m_input_fd);
	close(m_outpipe[PIPE_WRITE]);
	fclose(m_output_fd);
	close(m_errpipe[PIPE_WRITE]);
	fclose(m_error_fd);
}

void pipe_manager::attach_child_stdio()
{
	dup2(m_outpipe[PIPE_WRITE], STDOUT_FILENO);
	dup2(m_errpipe[PIPE_WRITE], STDERR_FILENO);
	dup2(m_inpipe[PIPE_READ], STDIN_FILENO);
	// Close the other part of the pipes
	fclose(m_input_fd);
	fclose(m_output_fd);
	fclose(m_error_fd);
}

void pipe_manager::enable_nonblocking(int fd)
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
	if(parsing_ok)
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
		g_log->error("Cannot parse Log from sdjagent: " + data);
	}
}

subprocesses_logger::subprocesses_logger(dragent_configuration *configuration, log_reporter* reporter) :
		m_configuration(configuration),
		m_log_reporter(reporter),
		m_max_fd(0),
		m_last_loop_ns(0)
{
	FD_ZERO(&m_readset);
	memset(&m_timeout, 0, sizeof(struct timeval));
	m_timeout.tv_sec = 1;
}

void subprocesses_logger::run()
{
	m_pthread_id = pthread_self();
	g_log->information("subprocesses_logger: Starting");

	while(!dragent_configuration::m_terminate)
	{
		m_last_loop_ns = sinsp_utils::get_current_time_ns();
		fd_set readset_w;
		memcpy(&readset_w, &m_readset, sizeof(fd_set));
		struct timeval timeout_w;
		memcpy(&timeout_w, &m_timeout, sizeof(timeval));

		int result = select(m_max_fd+1, &readset_w, NULL, NULL, &timeout_w);

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
						fds.second(data);
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
