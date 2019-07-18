#pragma once

#include "main.h"

class pipe_manager;

class monitored_process
{
public:
	monitored_process(std::string name, std::function<int(void)>&& exec, bool is_main=false):
		m_name(std::move(name)),
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
	std::string m_name;
	bool m_main;
	std::function<int(void)> m_exec;
	pid_t m_pid;
	bool m_enabled;
};

class monitor
{
public:
#ifndef CYGWING_AGENT
	monitor(std::string pidfile, std::string self);
#else
	monitor(std::string pidfile, bool windows_service_parent);
#endif
	int run();

	template<typename... Ts>
	void emplace_process(Ts&&... args)
	{
		m_processes.emplace_back(std::forward<Ts>(args)...);
	}

	void set_cleanup_function(std::function<void(void)>&& f)
	{
		m_cleanup_function = f;
	}

	static const uint8_t DONT_RESTART_EXIT_CODE = 17;
	static const uint8_t CONFIG_UPDATE_EXIT_CODE = 18;
	static const uint8_t DONT_SEND_LOG_REPORT_EXIT_CODE = 19;
private:
	std::function<void(void)> m_cleanup_function;
	std::string m_pidfile;
	std::vector<monitored_process> m_processes;
#ifndef CYGWING_AGENT
	std::string m_self_binary;
#else
	bool m_windows_service_parent = true;
#endif
};
