#pragma once

#include "main.h"

class pipe_manager;
void run_sdjagent(shared_ptr<pipe_manager>);
void run_monitor(const string& pidfile, shared_ptr<pipe_manager>);

class monitored_process
{
public:
	monitored_process(string name, function<void(void)> exec):
		m_name(move(name)),
		m_exec(move(exec)),
		m_pid(0)
	{}

	pid_t pid()
	{
		return m_pid;
	}

	void set_pid(pid_t pid)
	{
		m_pid = pid;
	}

	void exec()
	{
		m_exec();
	}

	bool is_main()
	{
		return m_main;
	}

	void set_main(bool value)
	{
		m_main = value;
	}

private:
	string m_name;
	bool m_main;
	function<void(void)> m_exec;
	pid_t m_pid{0};
};

class monitor
{
public:
	void run();
private:
	string m_pidfile;
	vector<monitored_process> m_processes;
};