
#include "Poco/SysdigModifiedFileChannel.h"
#include <Poco/Timestamp.h>
#include <string>


namespace dragent {

/**
 * A file channel that knows when a new file has been created then sets
 * the permissions of that file to have global read access. This is a
 * feature because the agent does an `umask 0027` at startup to turn off
 * global read for all files that are created.
 */
class globally_readable_file_channel : public Poco::SysdigModifiedFileChannel
{
public:
	globally_readable_file_channel(const std::string& log_path,
				       bool make_globally_readable);
private:
	void onRotate(const std::string& path) override;

	bool m_make_globally_readable;
};

}
