#include "capture.h"
#include "analyzer_utils.h"

#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

int capture_reader::stat(struct stat& s)
{
	if(m_read_fd < 0)
	{
		errno = EBADF;
		return -1;
	}

	return fstat(m_read_fd, &s);
}

ssize_t capture_reader::read_back(void* buf, size_t size)
{
	if(m_read_fd < 0)
	{
		errno = EBADF;
		return -1;
	}

	return read(m_read_fd, buf, size);
}

capture_reader::~capture_reader()
{
	if(m_read_fd >= 0)
	{
		close(m_read_fd);
	}
}

std::unique_ptr<capture> capture::start(sinsp* inspector, const std::string& filename, bool auto_delete)
{
	auto raw_capture = new capture;
	auto cap = std::unique_ptr<capture>(raw_capture);
	char errno_buf[256];

	cap->m_dumper = make_unique<sinsp_dumper>(inspector);
	cap->m_write_fd = open(filename.c_str(), O_WRONLY|O_CREAT|O_EXCL);
	if(cap->m_write_fd < 0)
	{
		strerror_r(errno, errno_buf, sizeof(errno_buf));
		throw sinsp_exception("Failed to create capture file " + filename + ": " + errno_buf);
	}

	cap->m_dumper->fdopen(cap->m_write_fd, false, true);
	// the dumper owns the write fd now
	cap->m_write_fd = -1;

	cap->m_read_fd = open(filename.c_str(), O_RDONLY);
	if(cap->m_read_fd < 0)
	{
		strerror_r(errno, errno_buf, sizeof(errno_buf));
		unlink(filename.c_str());
		throw sinsp_exception("Failed to reopen capture file " + filename + ": " + errno_buf);
	}

	if(auto_delete)
	{
		//UNLINK(2) the file will remain in existence until the last file descriptor referring to it is closed
		unlink(filename.c_str());
	}

	return cap;
}

std::unique_ptr<capture_reader> capture::make_reader()
{
	if(m_read_fd < 0)
	{
		throw sinsp_exception("Trying to get a second reader from a capture");
	}

	auto raw_reader = new capture_reader(m_read_fd);
	auto reader = std::unique_ptr<capture_reader>(raw_reader);
	m_read_fd = -1;
	return reader;
}

capture::~capture() {
	if(m_read_fd >= 0)
	{
		close(m_read_fd);
	}

	if(m_write_fd >= 0)
	{
		close(m_write_fd);
	}
}
