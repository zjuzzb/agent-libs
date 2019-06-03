#include "scoped_sinsp_logger_capture.h"
#include <logger.h>

namespace {

std::string s_captured;

void sinsp_logger_cb(std::string&& str,
		     const sinsp_logger::severity sev)
{
	switch (sev)
	{
	case sinsp_logger::SEV_FATAL:
		s_captured += "SEV_FATAL: ";
		break;

	case sinsp_logger::SEV_CRITICAL:
		s_captured += "SEV_CRITICAL: ";
		break;

	case sinsp_logger::SEV_ERROR:
		s_captured += "SEV_ERROR: ";
		break;

	case sinsp_logger::SEV_WARNING:
		s_captured += "SEV_WARNING: ";
		break;

	case sinsp_logger::SEV_NOTICE:
		s_captured += "SEV_NOTICE: ";
		break;

	case sinsp_logger::SEV_INFO:
		s_captured += "SEV_INFO: ";
		break;

	case sinsp_logger::SEV_DEBUG:
		s_captured += "SEV_DEBUG: ";
		break;

	case sinsp_logger::SEV_TRACE:
		s_captured += "SEV_TRACE: ";
		break;
	}

	s_captured += str;
}

}


namespace test_helpers
{

scoped_sinsp_logger_capture::scoped_sinsp_logger_capture()
{
	g_logger.add_callback_log(sinsp_logger_cb);
}

scoped_sinsp_logger_capture::~scoped_sinsp_logger_capture()
{
	s_captured.clear();
	g_logger.remove_callback_log();
}

bool scoped_sinsp_logger_capture::find(const char *value)
{
	return get().find(value) != std::string::npos;
}

const std::string &scoped_sinsp_logger_capture::get()
{
	return s_captured;
}

} // namespace test_helpers


