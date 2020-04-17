#include "common_logger.h"
#include "globally_readable_file_channel.h"
#include "Poco/DirectoryIterator.h"
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
	if(m_make_globally_readable)
	{
		chmod(path.c_str(), 0644);
	}
}

}
