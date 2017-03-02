#include "tracer_emitter.h"
#include <unistd.h>
#include <fcntl.h>

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
	if (m_fd > -1)
	{
		close(m_fd);
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
	if (m_fd < 0)
	{
		// open /dev/null for writing
		fprintf(stderr, "trying to open /dev/null\n");
		m_fd = ::open("/dev/null", O_WRONLY);
		if (m_fd < 0)
		{
			fprintf(stderr, "opening /dev/null failed %d\n", errno);
			return;
		}
	}

	// use stringstream instead?
	std::string wstr(enter ? ">" : "<");
	// 't' == use thread id
	wstr.append(":t:");
	wstr.append(m_tag);
	wstr.append("::");
	fprintf(stderr, "%s\n", wstr.c_str());
	::write(m_fd, wstr.c_str(), wstr.length());

	if (!enter)
	{
		m_exit_written = true;
	}
}
