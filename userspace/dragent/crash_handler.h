#pragma once

#include "main.h"

class crash_handler
{
public:
	static void run(int sig);
	static bool initialize();
};
