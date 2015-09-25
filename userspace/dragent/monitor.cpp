#include "monitor.h"
#include "configuration.h"
#include "Poco/Exception.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include "subprocesses_logger.h"
#include <thread>
#include <posix_queue.h>

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

int monitored_process::exec()
{
	prctl(PR_SET_PDEATHSIG, SIGKILL);
	// TODO: may be useful rename process?
	return m_exec();
}

monitor::monitor(string pidfile):
	m_pidfile(move(pidfile))
{
	create_pid_file(m_pidfile);
}

int monitor::run()
{
	signal(SIGINT, g_monitor_signal_callback);
	signal(SIGQUIT, g_monitor_signal_callback);
	signal(SIGTERM, g_monitor_signal_callback);
	signal(SIGUSR1, SIG_IGN);
	signal(SIGUSR2, SIG_IGN);

	for(auto& process : m_processes)
	{
		auto child_pid = fork();
		if(child_pid < 0)
		{
			exit(EXIT_FAILURE);
		}
		else if(child_pid == 0)
		{
			return process.exec();
		}
		else
		{
			process.set_pid(child_pid);
		}
	}

	while(g_signal_received == 0)
	{
		int status = 0;
		for(auto& process : m_processes)
		{
			if(!process.is_enabled())
			{
				continue;
			}

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

				if(!process.is_main())
				{
					if(WIFEXITED(status) && WEXITSTATUS(status) == DONT_RESTART_EXIT_CODE)
					{
						// errorcode=17 tells monitor to not retry
						// when a process fails (does not regard
						// our dragent)
						process.disable();
						continue;
					}

					// Notify main process to send log report
					for(const auto& process : m_processes)
					{
						if(process.is_main())
						{
							kill(process.pid(), SIGUSR2);
							break;
						}
					}
				}

				// crashed, restart it
				this_thread::sleep_for(chrono::seconds(1));

				auto child_pid = fork();
				if(child_pid < 0)
				{
					exit(EXIT_FAILURE);
				}
				else if(child_pid == 0)
				{
					return process.exec();
				}
				else
				{
					process.set_pid(child_pid);
				}
			}
		}
		this_thread::sleep_for(chrono::seconds(1));
	}

	for(const auto& process : m_processes)
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
		if(process.is_main())
		{
			waitpid(process.pid(), NULL, 0);
		}
	}

	for(const auto& queue : {"/sdchecks", "/dragent_app_checks", "/mounted_fs_reader_out"})
	{
		posix_queue::remove(queue);
	}
	delete_pid_file(m_pidfile);
	return(EXIT_SUCCESS);
}
