#include "crash_handler.h"
#include "sinsp_worker.h"

#ifndef CYGWING_AGENT
#include <execinfo.h>
#endif
#include <vector>


/**
 * Don't use the logging API here since the crash handler APIs are executed
 * in the context of signal handlers.  The write() system call is safe.
 *
 * Client code should use CRASHDUMP_ERROR, not CRASHDUMP_ERROR_.
 *
 * Note that the given msg must be a string literal
 */
#define CRASHDUMP_ERROR_(msg) write(STDERR_FILENO, (msg), strlen(msg))
#define CRASHDUMP_ERROR(msg) CRASHDUMP_ERROR_("crash_handler: " msg "\n")

/**
 * Get the length of the given fixed-size array.
 */
#define ARRAY_LENGTH(x) ((sizeof(x)/sizeof(0[x])) / ((size_t)(!(sizeof(x) % sizeof(0[x])))))

namespace
{

const int MAX_NUM_FRAMES = 20;
std::vector<char> m_crashdump_file(1);
const sinsp_worker* m_sinsp_worker = nullptr;

const int g_crash_signals[] =
{
	SIGSEGV,
	SIGABRT,
	SIGFPE,
	SIGILL,
	SIGBUS,
};

/**
 * Invoke an API provided by libgcc.  The motivation for this is to ensure that
 * the library is dynamically loaded before the agent tries to use APIs that it
 * provides in the context of signal handlers.
 *
 * From 'man 2 backtrace':
 * <blockquote>
 * backtrace() and backtrace_symbols_fd() don't call malloc() explicitly, but
 * they are part of libgcc, which gets loaded dynamically when first used.
 * Dynamic loading usually triggers a call to malloc(3).  If you need certain
 * calls to these two functions to not allocate memory (in signal handlers, for
 * example), you need to make sure libgcc is loaded beforehand.
 * </blockquote>
 */
void ensure_libgcc_is_loaded()
{
#ifndef CYGWING_AGENT
	void* array[MAX_NUM_FRAMES];

	backtrace(array, MAX_NUM_FRAMES);
#endif
}

/**
 * Write the given message of the given mlen to the given file descriptor.
 *
 * @param[in] message The message to write
 * @param[in] mlen    The length of the given message
 * @param[in] fd      The file descriptor to which to write the message
 */
void log_crashdump_message_internal(const char* const message,
                                    const size_t mlen,
                                    const int fd)
{
	// We expect fd to represent a file as compared to a network
	// connection, where an incomplete write might occur due to,
	// say, a socket buffer being full. So all incomplete writes
	// are considered errors.
	const size_t len = write(fd, message, mlen);

	if(len != mlen)
	{
		if(len == -1)
		{
			CRASHDUMP_ERROR("Could not write crash dump message");
		}
		else
		{
			CRASHDUMP_ERROR("Incomplete write when writing crash "
			                "dump message");
		}
	}
}

/**
 * Write the given message of the given mlen to the given file descriptors.
 * This variadic template version will accept two or more file descriptors.
 */
template<typename... Args>
void log_crashdump_message_internal(const char* const message,
                                    const size_t mlen,
                                    const int fd,
                                    Args... args)
{
	log_crashdump_message_internal(message, mlen, fd);
	log_crashdump_message_internal(message, mlen, args...);
}


/**
 * Handles all of the signals that the crash_handler handles.
 *
 * Note that this function executes in the context of signal handlers; it
 * must call only signal-safe functions.  See 'man 7 signal-safety'
 * (http://man7.org/linux/man-pages/man7/signal-safety.7.html).
 *
 * See more at:
 * https://wiki.sei.cmu.edu/confluence/display/c/SIG30-C.+Call+only+asynchronous-safe+functions+within+signal+handlers
 *
 * @param[in] sig The received signal number.
 */
void signal_handler(const int sig)
{
	if(g_log)
	{
		const int fd = open(m_crashdump_file.data(), O_WRONLY | O_APPEND);

		if(fd != -1)
		{
			char buf[1024];

			buf[sizeof(buf) - 1] = '\0';

			snprintf(buf, sizeof(buf) - 1, "Received signal %d\n", sig);
			log_crashdump_message_internal(buf, strlen(buf), STDOUT_FILENO, fd);

#ifndef CYGWING_AGENT
			void *array[MAX_NUM_FRAMES];
			const int frames = backtrace(array, MAX_NUM_FRAMES);

			snprintf(buf, sizeof(buf) - 1, "Backtrace frames: %d\n", frames);
			log_crashdump_message_internal(buf, strlen(buf), STDOUT_FILENO, fd);

			backtrace_symbols_fd(array, frames, fd);
			backtrace_symbols_fd(array, frames, STDOUT_FILENO);
#endif

			if(m_sinsp_worker && m_sinsp_worker->get_last_loop_ns())
			{
				const char* const msg = "Memory report:\n";
				log_crashdump_message_internal(msg, strlen(msg), STDOUT_FILENO, fd);

				// XXX: It's not clear that generate_memory_report
				//      is signal-safe
				m_sinsp_worker->get_inspector()->m_analyzer->generate_memory_report(buf, sizeof(buf));
				log_crashdump_message_internal(buf, strlen(buf), STDOUT_FILENO, fd);
			}

			close(fd);
		}
		else
		{
			CRASHDUMP_ERROR("Failed to open crashdump file");
			ASSERT(false);
		}
	}

	signal(sig, SIG_DFL);
	raise(sig);
}

} // end namespace


void crash_handler::log_crashdump_message(const char* const message)
{
	const size_t mlen = strlen(message);

	log_crashdump_message_internal(message, mlen, STDOUT_FILENO);

	const int fd = open(m_crashdump_file.data(), O_WRONLY | O_APPEND);
	if(fd > 0)
	{
		log_crashdump_message_internal(message, mlen, fd);
		close(fd);
	}
	else
	{
		CRASHDUMP_ERROR("Failed to open crashdump file");
	}
}

bool crash_handler::initialize()
{
	// Do this before we register any signal handlers.
	ensure_libgcc_is_loaded();

	stack_t stack = {};

	stack.ss_sp = new char[SIGSTKSZ];
	stack.ss_size = SIGSTKSZ;

	if(sigaltstack(&stack, NULL) == -1)
	{
		delete [] static_cast<char*>(stack.ss_sp);
		return false;
	}

	struct sigaction sa = {};
	sigemptyset(&sa.sa_mask);

	for(size_t j = 0; j < ARRAY_LENGTH(g_crash_signals); ++j)
	{
		sigaddset(&sa.sa_mask, g_crash_signals[j]);
	}

	sa.sa_handler = signal_handler;
	sa.sa_flags = SA_ONSTACK;

	for(size_t j = 0; j < ARRAY_LENGTH(g_crash_signals); ++j)
	{
		if(sigaction(g_crash_signals[j], &sa, NULL) != 0)
		{
			return false;
		}
	}

	return true;
}

std::vector<int> crash_handler::get_crash_signals()
{
	std::vector<int> handled_signals;

	for(size_t j = 0; j < ARRAY_LENGTH(g_crash_signals); ++j)
	{
		handled_signals.push_back(g_crash_signals[j]);
	}

	return handled_signals;
}

void crash_handler::set_crashdump_file(const std::string& crashdump_file)
{
	// std::string's c_str() can trigger dynamic memory allocation, which
	// isn't safe in the context of signal handlers.  Preallocate a
	// fixed-size buffer and copy the string into it.
	m_crashdump_file.resize(crashdump_file.size() + 1);

	strncpy(m_crashdump_file.data(),
	        crashdump_file.c_str(),
	        m_crashdump_file.size());
}

std::string crash_handler::get_crashdump_file()
{
	return std::string(m_crashdump_file.data());
}

void crash_handler::set_sinsp_worker(const sinsp_worker* const sinsp_worker)
{
	m_sinsp_worker = sinsp_worker;
}

const sinsp_worker* crash_handler::get_sinsp_worker()
{
	return m_sinsp_worker;
}
