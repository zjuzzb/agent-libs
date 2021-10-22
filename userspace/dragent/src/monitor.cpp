#include "exit_code.h"
#include "monitor.h"

#include "Poco/Exception.h"
#include "Poco/File.h"
#include "Poco/Process.h"

#include <sys/types.h>
#include <sys/wait.h>
#ifndef CYGWING_AGENT
#include <sys/prctl.h>
#else
#include "windows_helpers.h"
#endif
#include "subprocesses_logger.h"

#include <posix_queue.h>
#include <thread>

using namespace std;

static int g_signal_received = 0;
static bool g_sighup_received = false;

static void g_monitor_signal_callback(int sig)
{
	if (g_signal_received == 0)
	{
		g_signal_received = sig;
	}
}

static void g_monitor_sighup_callback(int)
{
	g_sighup_received = true;
}

static void create_pid_file(const string& pidfile)
{
	if (!pidfile.empty())
	{
		std::ofstream ostr(pidfile);
		if (ostr.good())
		{
			ostr << Poco::Process::id() << std::endl;
		}
	}
}

static void delete_pid_file(const string& pidfile)
{
	if (!pidfile.empty())
	{
		try
		{
			Poco::File f(pidfile);
			f.remove(true);
		}
		catch (Poco::Exception&)
		{
		}
	}
}

int monitored_process::exec()
{
#ifndef CYGWING_AGENT
	prctl(PR_SET_PDEATHSIG, SIGKILL);
#endif
	// TODO: may be useful rename process?
	return m_exec();
}

#ifndef CYGWING_AGENT
monitor::monitor(string pidfile, string self, const std::list<std::string>& restart_args)
    : m_pidfile(move(pidfile)),
      m_self_binary(move(self)),
      m_restart_args(restart_args)
#else
monitor::monitor(string pidfile, bool windows_service_parent)
    : m_pidfile(move(pidfile)),
      m_windows_service_parent(windows_service_parent)
#endif
{
	create_pid_file(m_pidfile);
}

int monitor::run()
{
	signal(SIGINT, g_monitor_signal_callback);
	signal(SIGQUIT, g_monitor_signal_callback);
	signal(SIGTERM, g_monitor_signal_callback);
	signal(SIGHUP, g_monitor_sighup_callback);
	signal(SIGUSR1, SIG_IGN);
	signal(SIGUSR2, SIG_IGN);

	for (auto& process : m_processes)
	{
		auto child_pid = fork();
		if (child_pid < 0)
		{
			delete_pid_file(m_pidfile);
			exit(EXIT_FAILURE);
		}
		else if (child_pid == 0)
		{
			return process.exec();
		}
		else
		{
			process.set_pid(child_pid);
		}
	}

	while (g_signal_received == 0)
	{
		int status = 0;
		if (g_sighup_received)
		{
			// Propagate SIGHUP to processes selectively
			for (auto& process : m_processes)
			{
				if (process.m_send_sighup)
				{
					kill(process.pid(), SIGHUP);
				}
			}
			g_sighup_received = false;
		}

		for (auto& process : m_processes)
		{
			if (!process.is_enabled())
			{
				continue;
			}

			auto waited_pid = waitpid(process.pid(), &status, WNOHANG);
			if (waited_pid < 0)
			{
				delete_pid_file(m_pidfile);
				exit(EXIT_FAILURE);
			}
			else if (waited_pid > 0)
			{
				if (process.is_main())  // sdagent
				{
					// Three cases:
					// 1) clean shutdown
					// 2) shutdown for config update
					// 3) crash
					//
					// for 2 and 3, we MUST execute the mjolnir cleanup and restart the
					// entire process, since the config might have changed. Ultimately,
					// if the process which is managing the config stuff cannot be
					// reliable (i.e. it can crash), we MUST reload config when it does
					if (WIFEXITED(status) && WEXITSTATUS(status) ==  dragent::exit_code::SHUT_DOWN)
					{
						//
						// Process terminated cleanly
						//
						delete_pid_file(m_pidfile);
						exit(EXIT_SUCCESS);
					}
					else if ((WIFEXITED(status) && WEXITSTATUS(status) == dragent::exit_code::CONFIG_UPDATE) || !WIFEXITED(status))
					{  // We either crashed or shutdown for config update
						for (const auto& process : m_processes)
						{
							//
							// Send TERM to all others
							if (!process.is_main())
							{
								if (kill(process.pid(), SIGKILL) != 0)
								{
									delete_pid_file(m_pidfile);
									exit(EXIT_FAILURE);
								}
								// locking wait here, but we are using SIGKILL
								// so it should not be a problem
								waitpid(process.pid(), NULL, 0);
							}
						}
						m_cleanup_function();
#ifndef CYGWING_AGENT

						std::vector<char*> argv;
						argv.push_back(const_cast<char*>(m_self_binary.c_str()));
						for (const auto& arg : m_restart_args)
						{
							argv.push_back(const_cast<char*>(arg.c_str()));
						}
						argv.push_back((char*)NULL);
						execv(m_self_binary.c_str(), &argv.front());
#else
						string executable =
						    windows_helpers::get_executable_parent_dir() + "/bin/dragent.exe";
						if (m_windows_service_parent)
						{
							execl(executable.c_str(), "dragent", "--serviceparent", (char*)NULL);
						}
						else
						{
							execl(executable.c_str(), "dragent", (char*)NULL);
						}
#endif

						delete_pid_file(m_pidfile);
						exit(EXIT_FAILURE);
					}
				}
				else  // Not sdagent
				{
					if (WIFEXITED(status) &&
					    WEXITSTATUS(status) == dragent::exit_code::DONT_RESTART)
					{
						// errorcode=17 tells monitor to not retry
						// when a process fails (does not regard
						// our dragent)
						process.disable();
						continue;
					}

					if (!WIFEXITED(status) ||
					    (WEXITSTATUS(status) != dragent::exit_code::DONT_SEND_LOG_REPORT))
					{
						std::cerr << "Process " << process.m_name
						          << " exited. Notifying sdagent process.\n";
						// Notify main process to send log report
						for (const auto& process : m_processes)
						{
							if (process.is_main())
							{
								kill(process.pid(), SIGUSR2);
								break;
							}
						}
					}
				}

				// If we reached here, the process crashed or it was purposefully killed
				// or it has exited with exit_code::RESTART
				this_thread::sleep_for(chrono::seconds(1));

				auto child_pid = fork();
				if (child_pid < 0)
				{
					delete_pid_file(m_pidfile);
					exit(EXIT_FAILURE);
				}
				else if (child_pid == 0)
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

	for (const auto& process : m_processes)
	{
		//
		// Signal received, forward it to the child and
		// wait for it to terminate
		//
		if (process.pid() > 0)
		{
			if (kill(process.pid(), g_signal_received) != 0)
			{
				delete_pid_file(m_pidfile);
				exit(EXIT_FAILURE);
			}
			if (process.is_main())
			{
				waitpid(process.pid(), NULL, 0);
			}
		}
	}

	m_cleanup_function();
	delete_pid_file(m_pidfile);
	return (EXIT_SUCCESS);
}
