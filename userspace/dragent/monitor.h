#pragma once

#include "main.h"

class pipe_manager;

class monitored_process
{
public:
	monitored_process(string name, function<int(void)>&& exec, bool is_main=false):
		m_name(move(name)),
		m_main(is_main),
		m_exec(exec),
		m_pid(0),
		m_enabled(true)
	{}

	pid_t pid() const
	{
		return m_pid;
	}

	void set_pid(pid_t pid)
	{
		m_pid = pid;
	}

	inline int exec();

	bool is_main() const
	{
		return m_main;
	}

	bool is_enabled() const
	{
		return m_enabled;
	}

	void disable()
	{
		m_enabled = false;
		m_pid = 0;
	}

private:
	string m_name;
	bool m_main;
	function<int(void)> m_exec;
	pid_t m_pid;
	bool m_enabled;
};

class monitor
{
public:
	monitor(string pidfile);
	int run();

	template<typename... Ts>
	void emplace_process(Ts&&... args)
	{
		m_processes.emplace_back(forward<Ts>(args)...);
	}

private:
	string m_pidfile;
	vector<monitored_process> m_processes;
};