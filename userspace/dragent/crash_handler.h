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

private:
	static const int NUM_FRAMES = 10;
	static string m_crashdump_file;
};
