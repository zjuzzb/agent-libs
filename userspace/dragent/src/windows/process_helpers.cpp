#include "../process_helpers.h"
#include "../logger.h"

COMMON_LOGGER("dragent");

namespace process_helpers
{

bool change_priority(int pid, int prio)
{
	LOG_INFO("Changing process priority is not supported on windows");
	return false;
}

}
