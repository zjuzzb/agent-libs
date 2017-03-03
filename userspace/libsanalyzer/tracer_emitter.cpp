#include "tracer_emitter.h"
// XXX ugh include mess
#include "sinsp.h"
#include "sinsp_int.h"
#include <unistd.h>
#include <fcntl.h>

tracer_writer::~tracer_writer()
{
	close_fd();
}

int tracer_writer::write(const std::string &trc)
{
	if (m_fd < 0)
	{
		// open /dev/null for writing
		fprintf(stderr, "trying to open /dev/null\n");
		m_fd = ::open("/dev/null", O_WRONLY|O_NONBLOCK|O_CLOEXEC);
		if (m_fd < 0)
		{
			fprintf(stderr, "opening /dev/null failed %d\n", errno);
			return m_fd;
		}
	}

	// Writes to /dev/null should always succeed,
	// but still error check just in case.
	auto ret = ::write(m_fd, trc.c_str(), trc.length());
	if (ret < 0 && errno == EINTR)
	{
		// Try once more before giving up
		ret = ::write(m_fd, trc.c_str(), trc.length());
	}

	if (ret < 0 && errno != EINTR)
	{
		// XXX log an error
		close_fd();
	}
	// We know ret >= 0 so size_t cast is safe
	else if ((size_t)ret != trc.length())
	{
		// XXX turn on after fixing includes
		ASSERT((size_t)ret == trc.length());

		// XXX log a different error? or one if block
		close_fd();
	}
	return ret;
}

void tracer_writer::close_fd()
{
	if (m_fd > -1)
	{
		::close(m_fd);
		m_fd = -1;
	}
}

tracer_emitter::tracer_emitter(std::string tag)
	: m_tag(std::move(tag))
{}

// XXX write a constexpr-compatible string class
// for compile time concatenation
tracer_emitter::tracer_emitter(std::string tag, const tracer_emitter &parent)
	: m_tag(parent.tag() + '.' + std::move(tag))
{}

tracer_emitter::~tracer_emitter()
{
	if (!m_exit_written)
	{
		write_tracer(false);
	}
}

void tracer_emitter::start()
{
	write_tracer(true);
}

void tracer_emitter::stop()
{
	write_tracer(false);
}

void tracer_emitter::write_tracer(const bool enter)
{
	static tracer_writer trc_writer;

	// use stringstream instead?
	std::string trc_str(enter ? ">" : "<");
	// 't' == use thread id
	trc_str.append(":t:");
	trc_str.append(m_tag);
	trc_str.append("::");

	fprintf(stderr, "%s\n", trc_str.c_str());
	trc_writer.write(trc_str);

	if (!enter)
	{
		m_exit_written = true;
	}
}
