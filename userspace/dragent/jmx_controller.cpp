#include "jmx_controller.h"
#include "logger.h"
#include <sys/prctl.h>
#include <sys/wait.h>

jmx_controller::jmx_controller(dragent_configuration *configuration) :
		configuration(configuration)
{
	// TODO: Check pipe return value
	pipe(m_inpipe);
	pipe(m_outpipe);
	pipe(m_errpipe);
	input_fd = fdopen(m_inpipe[PIPE_WRITE], "w");
	output_fd = fdopen(m_outpipe[PIPE_READ], "r");
	err_fd = fdopen(m_errpipe[PIPE_READ], "r");
}

pair<FILE*, FILE*> jmx_controller::get_io_fds()
{
	return make_pair(input_fd, output_fd);
}

void jmx_controller::run()
{
	// TODO: restart child when it crashes
	while(true)
	{
		pid_t child_pid = fork();
		if(child_pid == 0)
		{
			g_log->information("Starting sdjagent");
			// Child, bind pipes and exec
			dup2(m_outpipe[PIPE_WRITE], STDOUT_FILENO);
			dup2(m_errpipe[PIPE_WRITE], STDERR_FILENO);
			dup2(m_inpipe[PIPE_READ], STDIN_FILENO);

			prctl(PR_SET_PDEATHSIG, SIGKILL);

			execl("/usr/bin/java", "java", "-jar", "userspace/sdjagent/target/sdjagent-1.0-jar-with-dependencies.jar", (char *) NULL);
			g_log->warning("Cannot load sdjagent");
		}
		else
		{
			// Father, read from stderr and write to log
			// TODO: implement
			char buf[1000];
			while (true)
			{
				char *result = fgets(buf, 1000, err_fd);
				if (result == buf)
				{
					// Parse log level and use it
					g_log->information(buf);
				}
				else
				{
					// In this case probably process crashed
					waitpid(child_pid, NULL, 0);
					break;
				}
			}
		}
	}
}