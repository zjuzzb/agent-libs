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

static uint32_t get_restart_interval()
{
	Poco::Random rnd;
	rnd.seed();

	//
	// Return a number around RESTART_INTERVAL
	//
	return dragent_configuration::RESTART_INTERVAL - 
		rnd.next(dragent_configuration::RESTART_INTERVAL / 10);
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

	uint32_t seconds_to_restart = get_restart_interval();

	//
	// Father. It will be the monitor process
	//
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

			//
			// Every now and then, kill dragent just in case of some leak or
			// loop bug
			//
			if(--seconds_to_restart == 0)
			{
				kill(child_pid, SIGKILL);
				seconds_to_restart = get_restart_interval();
			}

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

		//
		// Since both child and father are run with --daemon option,
		// Poco can get confused and can delete the pidfile even if
		// the monitor doesn't die.
		//
		if(!pidfile.empty())
		{
			std::ofstream ostr(pidfile);
			if(ostr.good())
			{
				ostr << Poco::Process::id() << std::endl;
			}
		}

		//
		// Sleep for a bit and run another dragent
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
