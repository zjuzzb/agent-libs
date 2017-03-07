#include "tracer_emitter.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include <unistd.h>
#include <fcntl.h>

// Helper class to allow multiple tracer_emitter instances
// to share a single connection to /dev/null.
//
// XXX THIS CLASS IS CURRENTLY *NOT* THREADSAFE
// Multiple threads can ::write() to /dev/null safely, but
// the ::open() call and setting m_fd need locking to be used
// anywhere besides just in the sinsp_analyzer::flush() loop.
class tracer_writer
{
public:
	tracer_writer() {}
	~tracer_writer() { close_fd(); }

	int write(const std::string &trc);

private:
	void close_fd();

	int m_fd = -1;
};

int tracer_writer::write(const std::string &trc)
{
	if (m_fd < 0)
	{
		g_logger.log("Opening /dev/null for writing tracers",
			     sinsp_logger::SEV_DEBUG);
		m_fd = ::open("/dev/null", O_WRONLY|O_NONBLOCK|O_CLOEXEC);
		if (m_fd < 0)
		{
			g_logger.format(sinsp_logger::SEV_ERROR,
					"Unable to open /dev/null for writing tracers: %s",
					strerror(errno));
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
		g_logger.format(sinsp_logger::SEV_ERROR,
				"Unable to write tracer (%s) to /dev/null: %s",
				trc.c_str(), strerror(errno));
		close_fd();
	}
	// We know ret >= 0 so size_t cast is safe
	else if ((size_t)ret != trc.length())
	{
		ASSERT(false);
		g_logger.format(sinsp_logger::SEV_ERROR,
				"Incomplete write of tracer (%s) to /dev/null",
				trc.c_str());
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

// XXX find/write a constexpr-compatible string class
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

	// XXX can we constexpr this part too?
	std::string trc_str(enter ? ">" : "<");
	// 't' == use thread id
	trc_str.append(":t:");
	trc_str.append(m_tag);
	trc_str.append("::");

	trc_writer.write(trc_str);

	if (!enter)
	{
		m_exit_written = true;
	}
}
