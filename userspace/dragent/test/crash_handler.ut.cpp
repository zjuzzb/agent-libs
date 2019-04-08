/**
 * @file
 *
 * Unit tests for namespace crash_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "crash_handler.h"
#include "scoped_file_descriptor.h"
#include "scoped_temp_file.h"

#include <algorithm>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include <gtest.h>

namespace
{

const int MAX_NUM_SIGNALS = 65; // SIGRTMAX = 64


class crash_handler_test : public testing::Test
{
public:
	crash_handler_test():
		m_default_handlers()
	{ }

	/**
	 * Save any registered signal handlers so that they can be restored
	 * on tear-down.
	 */
	void SetUp()
	{
		for(size_t i = 1; i < MAX_NUM_SIGNALS; ++i)
		{
			m_default_handlers[i] = signal(i, SIG_DFL);

			// If there are any invalid signal numbers in the range,
			// ignore them.
			if(m_default_handlers[i] == SIG_ERR)
			{
				m_default_handlers[i] = SIG_DFL;
			}
		}
	}

	/**
	 * Restore the previously-saved signal handlers and reset the
	 * crashdump_file and sinsp_worker to their default values.
	 */
	void TearDown()
	{
		for(size_t i = 1; i < MAX_NUM_SIGNALS; ++i)
		{
			signal(i, m_default_handlers[i]);
		}
		crash_handler::set_crashdump_file("");
		crash_handler::set_sinsp_worker(nullptr);
	}

private:
	sighandler_t m_default_handlers[MAX_NUM_SIGNALS];
};

/**
 * Returns true if the given value is found in the given container, false
 * otherwise.
 */
template<typename ContainerType>
bool contains(const ContainerType& container, const int value)
{
	return std::find(container.begin(), container.end(), value) != container.end();
}

} // end namespace

/**
 * Ensure that the crash_handler is in the expected initial state.
 */
TEST_F(crash_handler_test, initial_state)
{
	const std::vector<int> handled_signals = crash_handler::get_crash_signals();

	ASSERT_EQ(handled_signals.size(), 5);
	ASSERT_TRUE(contains(handled_signals, SIGSEGV));
	ASSERT_TRUE(contains(handled_signals, SIGABRT));
	ASSERT_TRUE(contains(handled_signals, SIGFPE));
	ASSERT_TRUE(contains(handled_signals, SIGILL));
	ASSERT_TRUE(contains(handled_signals, SIGBUS));

	ASSERT_EQ(crash_handler::get_crashdump_file(), "");
	ASSERT_EQ(crash_handler::get_sinsp_worker(), nullptr);

	// Ensure that before initialize() is called, all interesting
	// signals have the default signal handlers.
	for (const auto& signum : handled_signals)
	{
		const sighandler_t handler = signal(signum, SIG_DFL);

		ASSERT_EQ(handler, SIG_DFL);
	}
}

/**
 * Ensure that initialize() registeres the expected signal handlers.
 * Ensure that set_crashdump_file() sets the crashdump filename.
 */
TEST_F(crash_handler_test, initialize)
{
	ASSERT_TRUE(crash_handler::initialize());

	const std::vector<int> handled_signals = crash_handler::get_crash_signals();

	// We can't access the signal handler function itself, but we can
	// make sure that the interesting signals no longer have the default
	// signal handler.
	for (const auto& signum : handled_signals)
	{
		const sighandler_t handler = signal(signum, SIG_DFL);

		ASSERT_NE(handler, SIG_DFL);
		ASSERT_NE(handler, SIG_ERR);
	}

	const std::string crashdump_file = "foo";

	crash_handler::set_crashdump_file(crashdump_file);
	ASSERT_EQ(crash_handler::get_crashdump_file(), crashdump_file);
}

/**
 * Set up the crash_handler, fork(), and then kill the child with one of
 * the signals that the crash_handler handles.  Ensure that the child dies
 * as a result of the delivered signal.
 *
 * Set up a pipe between the child and the parent, the child will redirect
 * standard output the the write end of the pipe.  The parent will
 * read that to verify that the child's crash_handler wrote the expected
 * output to standard output.
 *
 * Read the temp file to ensure that the expected output was written to the
 * file.
 */
TEST_F(crash_handler_test, handles_crash_segv)
{
	test_helpers::scoped_temp_file tmp_file;
	const int signum = SIGSEGV;
	int pipe_fds[2] = {};

	ASSERT_TRUE(tmp_file.created_successfully());
	ASSERT_TRUE(crash_handler::initialize());
	ASSERT_EQ(pipe(pipe_fds), 0);

	test_helpers::scoped_file_descriptor write_end(pipe_fds[1]);
	test_helpers::scoped_file_descriptor read_end(pipe_fds[0]);

	crash_handler::set_crashdump_file(tmp_file.get_filename());

	const pid_t pid = fork();

	ASSERT_TRUE(pid >= 0);

	if(pid == 0) // child
	{
		// Connect standard output to the write end of the pipe
		dup2(write_end.get_fd(), STDOUT_FILENO);

		write_end.close();
		read_end.close();

		raise(signum);
		_exit(1);
	}
	else // parent
	{
		const int MIN_PIPE_BUFFER_SIZE = 4096;
		char buffer[MIN_PIPE_BUFFER_SIZE] = {};
		int status = 0;

		write_end.close();

		ASSERT_EQ(waitpid(pid, &status, 0), pid);

		ASSERT_TRUE(WIFSIGNALED(status));
		ASSERT_EQ(WTERMSIG(status), signum);

		// Read what the child wrote to standard output
		ASSERT_TRUE(read(read_end.get_fd(), buffer, sizeof(buffer)) > 0);
		const std::string stdout_output(buffer);

		// Look for the right signal number.  We expect a stack trace
		// but we don't have a good way to search for that.
		ASSERT_NE(stdout_output.find("Received signal 11"),
		          std::string::npos);

		// Read what the child write to the crashdump file.
		test_helpers::scoped_file_descriptor fd(
				open(tmp_file.get_filename().c_str(), O_RDONLY));

		ASSERT_TRUE(fd.is_valid());

		memset(buffer, 0, sizeof(buffer));
		ASSERT_TRUE(read(fd.get_fd(), buffer, sizeof(buffer)) > 0);

		const std::string file_output(buffer);

		// Ensure that the content written to stdout matches the
		// content written to the file.
		ASSERT_EQ(stdout_output, file_output);
	}
}
