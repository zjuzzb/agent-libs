#pragma once

#include "main.h"

class sinsp_worker;

class crash_handler
{
public:
	static void run(int sig);
	static bool initialize();
	static void set_crashdump_file(const string& crashdump_file)
	{
		m_crashdump_file = crashdump_file;
	}
	static void set_sinsp_worker(const sinsp_worker* sinsp_worker)
	{
		m_sinsp_worker = sinsp_worker;
	}

	//
	// To be used in critical contexts where a malloc can't happen
	//
	static void log_crashdump_message(const char* message);

private:
	static void log_crashdump_message(int fd, const char* message);

	static const int NUM_FRAMES = 20;
	static string m_crashdump_file;
	static const sinsp_worker* m_sinsp_worker;
};
