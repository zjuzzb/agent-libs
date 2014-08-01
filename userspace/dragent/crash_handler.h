#pragma once

#include "main.h"

class crash_handler
{
public:
	static void run(int sig);
	static bool initialize();
	static void set_crashdump_file(const string& crashdump_file)
	{
		m_crashdump_file = crashdump_file;
	}

	//
	// To be used in critical contexts where a malloc can't happen
	//
	static void log_crashdump_message(const char* message);

private:
	static const int NUM_FRAMES = 10;
	static string m_crashdump_file;
};
