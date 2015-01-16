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
}

pair<int, int> jmx_controller::get_io_fds()
{
	return make_pair(m_inpipe[PIPE_WRITE], m_outpipe[PIPE_READ]);
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
			/*while (true)
		{
			char buf[200];
			read(m_errpipe[PIPE_READ], buf, 200);
			g_log->information(buf);
		}*/
			waitpid(child_pid, NULL, 0);
		}
	}
}