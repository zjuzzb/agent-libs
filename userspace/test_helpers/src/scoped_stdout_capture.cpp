#include "scoped_stdout_capture.h"
#include <fcntl.h>
#include <fstream>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

namespace test_helpers
{

scoped_stdout_capture::scoped_stdout_capture()
{
	fflush(stdout);
	m_stdout_fd = dup(STDOUT_FILENO);
	int redir_fd = open(m_redirected_file.get_filename().c_str(), O_WRONLY);
	dup2(redir_fd, STDOUT_FILENO);
	close(redir_fd);
	m_closed = false;
}

scoped_stdout_capture::~scoped_stdout_capture()
{
	put_stdout_back();
}

void scoped_stdout_capture::put_stdout_back()
{
	if(m_closed)
	{
		return;
	}

	fflush(stdout);
	dup2(m_stdout_fd, STDOUT_FILENO);
	close(m_stdout_fd);
	m_closed = true;
}

bool scoped_stdout_capture::find(const char *value)
{
	return get().find(value) != std::string::npos;
}

std::string scoped_stdout_capture::get()
{
	put_stdout_back();

	if(!m_redirected_file.created_successfully())
	{
		return std::string();
	}

	std::ifstream ifs(m_redirected_file.get_filename());
	std::string content((std::istreambuf_iterator<char>(ifs)),
                            (std::istreambuf_iterator<char>()));

	return content;
}

} // namespace test_helpers

