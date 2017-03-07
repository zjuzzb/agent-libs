#include "tracer_emitter.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include <unistd.h>
#include <fcntl.h>
#include <mutex>

thread_local int tls_fd = -1;

// Helper class to allow multiple tracer_emitter instances to
// share a single connection to /dev/null. Multiple threads can
// write safely and without locking by storing the /dev/null
// fd in thread local storage. Locking is only required when
// the fd is created or destroyed, and that should only happen
// at startup.
class tracer_writer
{
public:
	tracer_writer() {}
	~tracer_writer() { close_fd(); }

	void write(const std::string &trc);

private:
	int get_fd();
	void close_fd();

	int m_fd = -1;
	mutable std::mutex m_fd_lock;
};

void tracer_writer::write(const std::string &trc)
{
	if (tls_fd < 0)
	{
		tls_fd = get_fd();
		if (tls_fd < 0)
		{
			// Something is wrong with /dev/null,
			// so all writes are going to drop
			return;
		}
	}
	ASSERT(tls_fd >= 0);

	// Writes to /dev/null should always succeed.
	// Still, error check because if m_fd changes
	// for some reason, tls_fd needs to get
	// cleared so we pick up the new m_fd next time.
	auto ret = ::write(tls_fd, trc.c_str(), trc.length());
	if (ret < 0 && errno == EINTR)
	{
		// Try once more before giving up
		ret = ::write(tls_fd, trc.c_str(), trc.length());
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
	return;
}

int tracer_writer::get_fd()
{
	std::lock_guard<std::mutex> lock(m_fd_lock);

	if (m_fd >= 0)
	{
		return m_fd;
	}

	g_logger.log("Opening /dev/null for writing tracers",
		     sinsp_logger::SEV_DEBUG);
	m_fd = ::open("/dev/null", O_WRONLY|O_NONBLOCK|O_CLOEXEC);
	if (m_fd < 0)
	{
		g_logger.format(sinsp_logger::SEV_ERROR,
				"Unable to open /dev/null for writing tracers: %s",
				strerror(errno));
	}
	return m_fd;
}

void tracer_writer::close_fd()
{
	std::lock_guard<std::mutex> lock(m_fd_lock);

	if (m_fd > -1)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
				"Closing /dev/null (fd %d) for writing tracers",
				m_fd);
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
	ASSERT(!m_exit_written);
	if (!m_exit_written)
	{
		write_tracer(false);
	}
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
