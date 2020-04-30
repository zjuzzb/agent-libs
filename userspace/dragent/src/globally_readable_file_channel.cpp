#include "common_logger.h"
#include "globally_readable_file_channel.h"
#include "Poco/DirectoryIterator.h"
#include "Poco/Path.h"
#include <sys/stat.h>

COMMON_LOGGER();

namespace dragent
{

globally_readable_file_channel::globally_readable_file_channel(const std::string& log_path,
							       bool make_globally_readable) :
	Poco::SysdigModifiedFileChannel(log_path),
	m_make_globally_readable(make_globally_readable)
{
}

void globally_readable_file_channel::onRotate(const std::string& path)
{
	if(!m_make_globally_readable) return;

	// Set the permissions of the log file.
	chmod(path.c_str(), 0644);

	// In testing, the root_dir (default: /opt/draios) had 755 permissions
	// so the directory that needs to be updated is just the logs directory
	Poco::Path p(path);
	chmod(p.parent().toString().c_str(), 0755);
}

}
