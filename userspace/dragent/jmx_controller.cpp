#include "jmx_controller.h"
#include "logger.h"
#include <sys/prctl.h>
#include <sys/wait.h>


jmx_controller::jmx_controller(dragent_configuration *configuration) :
		configuration(configuration)
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
}

void jmx_controller::enable_nonblocking(int fd)
{
	int flags;
	flags = fcntl(fd, F_GETFL, 0);
	flags |= O_NONBLOCK;
	fcntl(fd, F_SETFL, flags);
}

pair<FILE*, FILE*> jmx_controller::get_io_fds()
{
	return make_pair(m_input_fd, m_output_fd);
}

void jmx_controller::run()
{
	g_log->information("Starting jmx_controller thread");
	pid_t child_pid = 0;
	while(!dragent_configuration::m_terminate)
	{
		child_pid = fork();
		if(child_pid == 0)
		{
			g_log->information("Starting sdjagent");
			// Child, bind pipes and exec
			dup2(m_outpipe[PIPE_WRITE], STDOUT_FILENO);
			dup2(m_errpipe[PIPE_WRITE], STDERR_FILENO);
			dup2(m_inpipe[PIPE_READ], STDIN_FILENO);

			prctl(PR_SET_PDEATHSIG, SIGKILL);

			execl("/usr/bin/java", "java", "-Djava.library.path=/opt/draios/lib", "-jar", "/opt/draios/share/sdjagent.jar", (char *) NULL);
			g_log->warning("Cannot load sdjagent, errno: "+ errno);
			exit(1);
		}
		else
		{
			// Father, read from stderr and write to log
			while (!dragent_configuration::m_terminate)
			{
				fd_set readset;
				FD_ZERO(&readset);
				FD_SET(m_errpipe[PIPE_READ], &readset);
				struct timeval timeout;
				memset(&timeout, 0, sizeof(struct timeval));
				timeout.tv_sec = 1;
				int result = select(m_errpipe[PIPE_READ]+1, &readset, NULL, NULL, &timeout);

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
				else
				{
					// There is no log data, check if process is down
					pid_t waited_pid = waitpid(child_pid, NULL, WNOHANG);
					if (waited_pid == child_pid)
					{
						// Stop this loop and fork again
						child_pid = 0;
						break;
					}
				}
			}
		}
	}
	if (child_pid)
	{
		g_log->information("Sending SIGTERM to sdjagent");
		kill(child_pid, SIGTERM);
		pid_t waited_pid = waitpid(child_pid, NULL, 0);
		if (waited_pid == child_pid)
		{
			g_log->information("sdjagent terminated");
		}
	}
	g_log->information("jmx_controller terminating");
}
