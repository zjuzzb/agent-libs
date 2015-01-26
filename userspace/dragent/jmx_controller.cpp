#include "jmx_controller.h"
#include "logger.h"

pipe_manager::pipe_manager()
{
	// TODO: Check pipe return value
	// Create pipes
	pipe(m_inpipe);
	pipe(m_outpipe);
	pipe(m_errpipe);

	// transform to FILE*
	m_input_fd = fdopen(m_inpipe[PIPE_WRITE], "w");
	m_output_fd = fdopen(m_outpipe[PIPE_READ], "r");
	m_error_fd = fdopen(m_errpipe[PIPE_READ], "r");

	// Use non blocking io
	enable_nonblocking(m_outpipe[PIPE_READ]);
	enable_nonblocking(m_errpipe[PIPE_READ]);
	enable_nonblocking(m_inpipe[PIPE_WRITE]);
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
}

void pipe_manager::enable_nonblocking(int fd)
{
	int flags;
	flags = fcntl(fd, F_GETFL, 0);
	flags |= O_NONBLOCK;
	fcntl(fd, F_SETFL, flags);
}

jmx_controller::jmx_controller(dragent_configuration *configuration, FILE* error_fd) :
		configuration(configuration),
		m_error_fd(error_fd)
{
}

void jmx_controller::run()
{
	g_log->information("jmx_controller: Starting");
	while(!dragent_configuration::m_terminate)
	{
		fd_set readset;
		FD_ZERO(&readset);
		FD_SET(fileno(m_error_fd), &readset);
		struct timeval timeout;
		memset(&timeout, 0, sizeof(struct timeval));
		timeout.tv_sec = 1;
		int result = select(fileno(m_error_fd)+1, &readset, NULL, NULL, &timeout);

		if (result > 0 )
		{
			string json_data;
			char buffer[READ_BUFFER_SIZE] = "";
			char* fgets_res = fgets(buffer, READ_BUFFER_SIZE, m_error_fd);
			while (fgets_res != NULL && strstr(buffer, "\n") == NULL)
			{
				json_data.append(buffer);
				fgets_res = fgets(buffer, READ_BUFFER_SIZE, m_error_fd);
			}
			json_data.append(buffer);

			// Parse log level and use it
			Json::Value sdjagent_log;
			bool parsing_ok = m_json_reader.parse(json_data, sdjagent_log, false);
			if (parsing_ok)
			{
				string log_level = sdjagent_log["level"].asString();
				string log_message = "sdjagent, " + sdjagent_log["message"].asString();
				if (log_level == "SEVERE")
				{
					g_log->error(log_message);
				}
				else if (log_level == "WARNING")
				{
					g_log->warning(log_message);
				}
				else if (log_level == "INFO")
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
				g_log->error("Cannot parse Log from sdjagent: " + json_data);
			}
		}
	}
	g_log->information("jmx_controller terminating");
}
