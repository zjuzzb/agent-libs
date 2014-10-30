#include "monitor.h"
#include "configuration.h"

#include <sys/types.h>
#include <sys/wait.h>

static int g_signal_received = 0;

static void g_monitor_signal_callback(int sig)
{
	if(g_signal_received == 0)
	{
		g_signal_received = sig;
	}
}

void run_monitor(const string& pidfile)
{
	signal(SIGINT, g_monitor_signal_callback);
	signal(SIGQUIT, g_monitor_signal_callback);
	signal(SIGTERM, g_monitor_signal_callback);
	signal(SIGUSR1, SIG_IGN);

	//
	// Start the monitor process
	// 
	pid_t child_pid = fork();
	if(child_pid < 0)
	{
		exit(EXIT_FAILURE);
	}

	if(child_pid == 0)
	{
		//
		// Child. Continue execution
		//
		return;
	}

	//
	// Father. It will be the monitor process
	//
	{
		std::ofstream ostr(pidfile);
		if(ostr.good())
		{
			ostr << Poco::Process::id() << std::endl;
		}
		Poco::TemporaryFile::registerForDeletion(pidfile);
	}

	while(g_signal_received == 0)
	{
		int status = 0;
		pid_t waited_pid = waitpid(child_pid, &status, WNOHANG);

		if(waited_pid < 0)
		{
			exit(EXIT_FAILURE);
		}

		if(waited_pid == 0)
		{
			//
			// Child still alive
			//
			sleep(1);
			continue;
		}

		child_pid = 0;

		if(WIFEXITED(status) && WEXITSTATUS(status) == 0)
		{
			//
			// Process terminated cleanly
			//
			exit(EXIT_SUCCESS);
		}

		//
		// Process terminated abnormally, restart it
		//
		sleep(1);

		child_pid = fork();
		if(child_pid < 0)
		{
			exit(EXIT_FAILURE);
		}

		if(child_pid == 0)
		{
			//
			// Child. Continue execution
			//
			return;
		}
	}

	if(child_pid)
	{
		//
		// Signal received, forward it to the child and
		// wait for it to terminate
		//
		if(kill(child_pid, g_signal_received) != 0)
		{
			exit(EXIT_FAILURE);
		}

		waitpid(child_pid, NULL, 0);
	}

	exit(EXIT_SUCCESS);
}
