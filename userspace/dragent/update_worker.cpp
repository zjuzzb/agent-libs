#include "update_worker.h"

#include <sys/types.h>
#include <sys/wait.h>

#include "logger.h"

update_worker::update_worker(dragent_configuration* configuration):
	m_configuration(configuration)
{

}

void update_worker::run()
{
	SharedPtr<update_worker> ptr(this);

	g_log->information("Starting agent update");

	if(!m_configuration->m_autoupdate_enabled)
	{
		g_log->information("Auto update disabled");
		return;
	}

	File debian_version("/etc/debian_version");
	File system_release_cpe("/etc/system-release-cpe");

	if(debian_version.exists())
	{
		g_log->information("Detected Debian system");
		update_debian();
	}
	else if(system_release_cpe.exists())
	{
		g_log->information("Detected RHEL system");
		update_rhel();
	}
	else
	{
		g_log->error("Unable to detect system flavor");
	}
}

void update_worker::update_debian()
{
	{
		string command = "apt-get";
		vector<string> args;
		args.push_back("update");
		launch(command, args);
	}

	{
		string command = "apt-get";
		vector<string> args;
		args.push_back("-y");
		args.push_back("install");
		args.push_back("draios-agent");
		launch(command, args);
	}
}

void update_worker::update_rhel()
{
	{
		string command = "yum";
		vector<string> args;
		args.push_back("clean");
		args.push_back("expire-cache");
		launch(command, args);
	}

	{
		string command = "yum";
		vector<string> args;
		args.push_back("-y");
		args.push_back("install");
		args.push_back("draios-agent");
		launch(command, args);
	}
}

void update_worker::launch(const string& command, const vector<string> args)
{
	g_log->information("Running '" + command + "'");

	Pipe output;
	ProcessHandle handle = Process::launch(command, args, NULL, &output, &output);
	pid_t pid = handle.id();

	int ret;

	while(!dragent_configuration::m_terminate)
	{
		int status;
		pid_t waited_pid = waitpid(pid, &status, WNOHANG);

		if(waited_pid == 0)
		{
			//
			// Child still alive
			//
			Thread::sleep(100);
			continue;
		}

		if(WIFEXITED(status))
		{
			ret = WEXITSTATUS(status);

			Poco::PipeInputStream istr(output);
			string soutput;
			
			StreamCopier::copyToString(istr, soutput);

			g_log->information("Update returned " + Poco::NumberFormatter::format(ret) + ": " + soutput);
		}

		break;
	}
}
