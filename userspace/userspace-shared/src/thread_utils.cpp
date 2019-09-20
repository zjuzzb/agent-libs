/**
 * @file
 *
 * Implementation of thread-related helper APIs.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "thread_utils.h"
#include <sys/syscall.h>
#include <unistd.h>

pid_t thread_utils::get_tid()
{
	static thread_local pid_t tid;

	if(tid == 0)
	{
		tid = syscall(SYS_gettid);
	}

	return tid;
}
