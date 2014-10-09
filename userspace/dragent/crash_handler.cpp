#include "crash_handler.h"

#include <execinfo.h>

#include "logger.h"

string crash_handler::m_crashdump_file;

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
	if(g_log)
	{
		char line[128];
		snprintf(line, sizeof(line), "Received signal %d\n", sig);
		log_crashdump_message(line);

		void *array[NUM_FRAMES];
		int frames = backtrace(array, NUM_FRAMES);
		int fd = open(m_crashdump_file.c_str(), O_WRONLY|O_APPEND);
		if(fd != -1)
		{
			backtrace_symbols_fd(array, frames, fd);
			close(fd);
		}
		else
		{
			ASSERT(false);
		}

		backtrace_symbols_fd(array, frames, 1);
	}

	signal(sig, SIG_DFL);
	raise(sig);
}

void crash_handler::log_crashdump_message(const char* message)
{
	int fd = open(m_crashdump_file.c_str(), O_WRONLY|O_APPEND);
	if(fd != -1)
	{
		write(fd, message, strlen(message));
		close(fd);
	}
	else
	{
		ASSERT(false);
	}

	write(1, message, strlen(message));	
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

	void *array[NUM_FRAMES];
	backtrace(array, NUM_FRAMES);

	return true;
}
