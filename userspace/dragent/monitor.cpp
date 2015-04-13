#include "monitor.h"
#include "configuration.h"
#include "Poco/Exception.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include "subprocesses_logger.h"
#include <thread>

static int g_signal_received = 0;

static void g_monitor_signal_callback(int sig)
{
	if(g_signal_received == 0)
	{
		g_signal_received = sig;
	}
}

static void create_pid_file(const string& pidfile)
{
	if(!pidfile.empty())
	{
		std::ofstream ostr(pidfile);
		if(ostr.good())
		{
			ostr << Poco::Process::id() << std::endl;
		}
	}
}

static void delete_pid_file(const string& pidfile)
{
	if(!pidfile.empty())
	{
		try
		{
			File f(pidfile);
			f.remove(true);
		}
		catch(Poco::Exception&)
		{
		}
	}
}

void monitored_process::exec()
{
	prctl(PR_SET_PDEATHSIG, SIGKILL);
	// TODO: may be useful rename process?
	m_exec();
}

int monitor::run()
{
	signal(SIGINT, g_monitor_signal_callback);
	signal(SIGQUIT, g_monitor_signal_callback);
	signal(SIGTERM, g_monitor_signal_callback);
	signal(SIGUSR1, SIG_IGN);

	for(auto& process : m_processes)
	{
		auto child_pid = fork();
		if(child_pid < 0)
		{
			exit(EXIT_FAILURE);
		}
		else if(child_pid == 0)
		{
			process.exec();
		}
		else
		{
			process.set_pid(child_pid);
		}
	}

	create_pid_file(m_pidfile);

	while(g_signal_received == 0)
	{
		int status = 0;
		for(auto& process : m_processes)
		{
			auto waited_pid = waitpid(process.pid(), &status, WNOHANG);
			if(waited_pid < 0)
			{
				delete_pid_file(m_pidfile);
				exit(EXIT_FAILURE);
			}
			else if(waited_pid > 0)
			{
				if(process.is_main() && WIFEXITED(status) && WEXITSTATUS(status) == 0)
				{
					//
					// Process terminated cleanly
					//
					delete_pid_file(m_pidfile);
					exit(EXIT_SUCCESS);
				}

				// crashed, restart it
				this_thread::sleep_for(chrono::seconds(1));

				// Notify main process to send log report
				if(!process.is_main())
				{
					for(auto& process : m_processes)
					{
						if(process.is_main())
						{
							kill(process.pid(), SIGUSR2);
							break;
						}
					}
				}

				auto child_pid = fork();
				if(child_pid < 0)
				{
					exit(EXIT_FAILURE);
				}
				else if(child_pid == 0)
				{
					process.exec();
				}
				else
				{
					process.set_pid(child_pid);
				}
			}
		}
		this_thread::sleep_for(chrono::seconds(1));
	}

	for(auto& process : m_processes)
	{
		//
		// Signal received, forward it to the child and
		// wait for it to terminate
		//
		if(kill(process.pid(), g_signal_received) != 0)
		{
			delete_pid_file(m_pidfile);
			exit(EXIT_FAILURE);
		}
		waitpid(process.pid(), NULL, 0);
	}

	delete_pid_file(m_pidfile);
	return(EXIT_SUCCESS);
}