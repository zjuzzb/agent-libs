#include "crash_handler.h"

#include <execinfo.h>

#include "logger.h"

static const int g_crash_signals[] = 
{
	SIGSEGV,
	SIGABRT,
	SIGFPE,
	SIGILL,
	SIGBUS
};

void crash_handler::run(int sig)
{
	static int NUM_FRAMES = 10;

	if(g_log)
	{
		g_log->error("Received signal " + NumberFormatter::format(sig));

		void *array[NUM_FRAMES];

		int frames = backtrace(array, NUM_FRAMES);
		
		char **strings = backtrace_symbols(array, frames);
		
		if(strings != NULL)
		{
			for(int32_t j = 0; j < frames; ++j)
			{
				g_log->error(strings[j]);
			}

			free(strings);
		}
	}

	signal(sig, SIG_DFL);
	raise(sig);
}

bool crash_handler::initialize()
{
	stack_t stack;

	memset(&stack, 0, sizeof(stack));
	stack.ss_sp = malloc(SIGSTKSZ);
	stack.ss_size = SIGSTKSZ;

	if(sigaltstack(&stack, NULL) == -1)
	{
		free(stack.ss_sp);
		return false;
	}

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);

	for(uint32_t j = 0; j < sizeof(g_crash_signals) / sizeof(g_crash_signals[0]); ++j)
	{
		sigaddset(&sa.sa_mask, g_crash_signals[j]);
	}

	sa.sa_handler = crash_handler::run;
	sa.sa_flags = SA_ONSTACK;

	for(uint32_t j = 0; j < sizeof(g_crash_signals) / sizeof(g_crash_signals[0]); ++j)
	{
		if(sigaction(g_crash_signals[j], &sa, NULL) != 0)
		{
			return false;
		}
	}

	return true;
}
