#include "capture.h"
#include "analyzer_utils.h"

#include <cerrno>
#include <fcntl.h>
#include <unistd.h>

std::unique_ptr<capture> capture::start(sinsp* inspector, const std::string& filename)
{
	auto raw_capture = new capture;
	auto cap = std::unique_ptr<capture>(raw_capture);

	cap->m_dumper = make_unique<sinsp_dumper>(inspector);
	cap->m_dumper->open(filename, false, true);

	return cap;
}

capture::~capture() {
}
