#pragma once

namespace process_helpers
{

/**
 * Change the priority of a process
 *
 * @param pid process identifier
 * @param prio the priority to set the process to
 *
 * @return true if successful
 */
bool change_priority(int pid, int prio);


}
