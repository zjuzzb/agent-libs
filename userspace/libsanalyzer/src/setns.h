#pragma once

// Use raw setns syscall for versions of glibc that don't include it (namely glibc-2.12)
#if __GLIBC__ == 2 && __GLIBC_MINOR__ < 14
//#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#if defined(__NR_setns) && !defined(SYS_setns)
#define SYS_setns __NR_setns
#endif
#ifdef SYS_setns
inline int setns(int fd, int nstype)
{
	return syscall(SYS_setns, fd, nstype);
}
#endif
#else
#include <sched.h>
#endif
