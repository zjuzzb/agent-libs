
#include "dragent/process_helpers.h"
#include <sys/resource.h>

namespace process_helpers
{

bool change_priority(int pid, int prio)
{
	const int result = setpriority(PRIO_PROCESS, pid, prio);
	return result == 0;
}

}
