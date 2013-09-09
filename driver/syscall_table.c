#include <linux/cdev.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kdev_t.h>
#include <linux/delay.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/wait.h>
#include <asm/syscall.h>
#include <net/sock.h>
#include <asm/unistd.h>

#include "ppm_ringbuffer.h"
#include "ppm_events_public.h"
#include "ppm_events.h"
#include "ppm.h"

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
// SYSCALL TABLE
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
const struct syscall_evt_pair g_syscall_table[SYSCALL_TABLE_SIZE] =
{
#ifdef __NR_open
	[__NR_open] = 			{1, PPME_SYSCALL_OPEN_E, PPME_SYSCALL_OPEN_X},
#endif
#ifdef __NR_creat
	[__NR_creat] = 			{1, PPME_SYSCALL_CREAT_E, PPME_SYSCALL_CREAT_X},
#endif
#ifdef __NR_close
	[__NR_close] = 			{1, PPME_SYSCALL_CLOSE_E, PPME_SYSCALL_CLOSE_X},
#endif
#ifdef __NR_brk
	[__NR_brk] = 			{1, PPME_SYSCALL_BRK_E, PPME_SYSCALL_BRK_X},
#endif
#ifdef __NR_read
	[__NR_read] = 			{1, PPME_SYSCALL_READ_E, PPME_SYSCALL_READ_X},
#endif
#ifdef __NR_write
	[__NR_write] = 			{1, PPME_SYSCALL_WRITE_E, PPME_SYSCALL_WRITE_X},
#endif
#ifdef __NR_execve
	[__NR_execve] = 		{1, PPME_SYSCALL_EXECVE_E, PPME_SYSCALL_EXECVE_X},
#endif
#ifdef __NR_clone
	[__NR_clone] = 			{1, PPME_CLONE_E, PPME_CLONE_X},
#endif
//	[__NR_exit] = 			{1, PPME_SYSCALL_EXIT_E, PPME_SYSCALL_EXIT_EXIT},
//	[__NR_socketcall] = 	{1, PPME_GENERIC_E, PPME_GENERIC_EXIT},
#ifdef __NR_pipe
	[__NR_pipe] = 			{1, PPME_SYSCALL_PIPE_E, PPME_SYSCALL_PIPE_X},
#endif
#ifdef __NR_pipe2
	[__NR_pipe2] = 			{1, PPME_SYSCALL_PIPE_E, PPME_SYSCALL_PIPE_X},
#endif
#ifdef __NR_eventfd
	[__NR_eventfd] = 		{1, PPME_SYSCALL_EVENTFD_E, PPME_SYSCALL_EVENTFD_X},
#endif
#ifdef __NR_eventfd2
	[__NR_eventfd2] = 		{1, PPME_SYSCALL_EVENTFD_E, PPME_SYSCALL_EVENTFD_X},
#endif
#ifdef __NR_futex
	[__NR_futex] = 			{1, PPME_SYSCALL_FUTEX_E, PPME_SYSCALL_FUTEX_X},
#endif
#ifdef __NR_stat
	[__NR_stat] = 			{1, PPME_SYSCALL_STAT_E, PPME_SYSCALL_STAT_X},
#endif
#ifdef __NR_lstat
	[__NR_lstat] = 			{1, PPME_SYSCALL_LSTAT_E, PPME_SYSCALL_LSTAT_X},
#endif
#ifdef __NR_fstat
	[__NR_fstat] = 			{1, PPME_SYSCALL_FSTAT_E, PPME_SYSCALL_FSTAT_X},
#endif
#ifdef __NR_epoll_wait
	[__NR_epoll_wait] = 	{1, PPME_SYSCALL_EPOLLWAIT_E, PPME_SYSCALL_EPOLLWAIT_X},
#endif
#ifdef __NR_poll
	[__NR_poll] = 			{1, PPME_SYSCALL_POLL_E, PPME_SYSCALL_POLL_X},
#endif
#ifdef __NR_select
	[__NR_select] = 		{1, PPME_SYSCALL_SELECT_E, PPME_SYSCALL_SELECT_X},
#endif
#ifdef __NR_lseek
	[__NR_lseek] = 			{1, PPME_SYSCALL_LSEEK_E, PPME_SYSCALL_LSEEK_X},
#endif
#ifdef __NR_ioctl
	[__NR_ioctl] = 			{1, PPME_SYSCALL_IOCTL_E, PPME_SYSCALL_IOCTL_X},
#endif
#ifdef __NR_getcwd
	[__NR_getcwd] = 		{1, PPME_SYSCALL_GETCWD_E, PPME_SYSCALL_GETCWD_X},
#endif
#ifdef __NR_chdir
	[__NR_chdir] = 			{1, PPME_SYSCALL_CHDIR_E, PPME_SYSCALL_CHDIR_X},
#endif
#ifdef __NR_fchdir
	[__NR_fchdir] = 		{1, PPME_SYSCALL_FCHDIR_E, PPME_SYSCALL_FCHDIR_X},
#endif
#ifdef __NR_mkdir
	[__NR_mkdir] = 			{1, PPME_SYSCALL_MKDIR_E, PPME_SYSCALL_MKDIR_X},
#endif
#ifdef __NR_rmdir
	[__NR_rmdir] = 			{1, PPME_SYSCALL_RMDIR_E, PPME_SYSCALL_RMDIR_X},
#endif
#ifdef __NR_openat
	[__NR_openat] = 		{1, PPME_SYSCALL_OPENAT_E, PPME_SYSCALL_OPENAT_X},
#endif
#ifdef __NR_link
	[__NR_link] = 			{1, PPME_SYSCALL_LINK_E, PPME_SYSCALL_LINK_X},
#endif
#ifdef __NR_linkat
	[__NR_linkat] = 		{1, PPME_SYSCALL_LINKAT_E, PPME_SYSCALL_LINKAT_X},
#endif
#ifdef __NR_unlink
	[__NR_unlink] = 		{1, PPME_SYSCALL_UNLINK_E, PPME_SYSCALL_UNLINK_X},
#endif
#ifdef __NR_unlinkat
	[__NR_unlinkat] = 		{1, PPME_SYSCALL_UNLINKAT_E, PPME_SYSCALL_UNLINKAT_X},
#endif
#ifdef __NR_pread64
	[__NR_pread64] = 		{1, PPME_SYSCALL_PREAD_E, PPME_SYSCALL_PREAD_X},
#endif
#ifdef __NR_pwrite64
	[__NR_pwrite64] = 		{1, PPME_SYSCALL_PWRITE_E, PPME_SYSCALL_PWRITE_X},
#endif
#ifdef __NR_readv
	[__NR_readv] = 			{1, PPME_SYSCALL_READV_E, PPME_SYSCALL_READV_X},
#endif
#ifdef __NR_writev
	[__NR_writev] = 		{1, PPME_SYSCALL_WRITEV_E, PPME_SYSCALL_WRITEV_X},
#endif
#ifdef __NR_preadv
	[__NR_preadv] = 		{1, PPME_SYSCALL_PREADV_E, PPME_SYSCALL_PREADV_X},
#endif
#ifdef __NR_pwritev
	[__NR_pwritev] = 		{1, PPME_SYSCALL_PWRITEV_E, PPME_SYSCALL_PWRITEV_X},
#endif
#ifdef __NR_dup
	[__NR_dup] = 			{1, PPME_SYSCALL_DUP_E, PPME_SYSCALL_DUP_X},
#endif
#ifdef __NR_dup2
	[__NR_dup2] = 			{1, PPME_SYSCALL_DUP_E, PPME_SYSCALL_DUP_X},
#endif
#ifdef __NR_dup3
	[__NR_dup3] = 			{1, PPME_SYSCALL_DUP_E, PPME_SYSCALL_DUP_X},
#endif
#ifdef __NR_signalfd
	[__NR_signalfd] = 		{1, PPME_SYSCALL_SIGNALFD_E, PPME_SYSCALL_SIGNALFD_X},
#endif
#ifdef __NR_signalfd4
	[__NR_signalfd4] = 		{1, PPME_SYSCALL_SIGNALFD_E, PPME_SYSCALL_SIGNALFD_X},
#endif
#ifdef __NR_kill
	[__NR_kill] = 			{1, PPME_SYSCALL_KILL_E, PPME_SYSCALL_KILL_X},
#endif
#ifdef __NR_tkill
	[__NR_tkill] =	 		{1, PPME_SYSCALL_TKILL_E, PPME_SYSCALL_TKILL_X},
#endif
#ifdef __NR_tgkill
	[__NR_tgkill] = 		{1, PPME_SYSCALL_TGKILL_E, PPME_SYSCALL_TGKILL_X},
#endif
#ifdef __NR_nanosleep
	[__NR_nanosleep] = 		{1, PPME_SYSCALL_NANOSLEEP_E, PPME_SYSCALL_NANOSLEEP_X},
#endif
#ifdef __NR_timerfd_create
	[__NR_timerfd_create] =	{1, PPME_SYSCALL_TIMERFD_CREATE_E, PPME_SYSCALL_TIMERFD_CREATE_X},
#endif
#ifdef __NR_inotify_init
	[__NR_inotify_init] =	{1, PPME_SYSCALL_INOTIFY_INIT_E, PPME_SYSCALL_INOTIFY_INIT_X},
#endif
#ifdef __NR_inotify_init1
	[__NR_inotify_init1] =	{1, PPME_SYSCALL_INOTIFY_INIT_E, PPME_SYSCALL_INOTIFY_INIT_X},
#endif
#ifdef __NR_getrlimit
	[__NR_getrlimit] =		{1, PPME_SYSCALL_GETRLIMIT_E, PPME_SYSCALL_GETRLIMIT_X},
#endif
#ifdef __NR_setrlimit
	[__NR_setrlimit] =		{1, PPME_SYSCALL_SETRLIMIT_E, PPME_SYSCALL_SETRLIMIT_X},
#endif
#ifdef __NR_prlimit64
	[__NR_prlimit64] =		{1, PPME_SYSCALL_PRLIMIT_E, PPME_SYSCALL_PRLIMIT_X},
#endif
#ifdef __NR_ugetrlimit
	[__NR_ugetrlimit] =		{1, PPME_SYSCALL_GETRLIMIT_E, PPME_SYSCALL_GETRLIMIT_X},
#endif
#ifdef __NR_ppoll 
//	[__NR_ppoll] = 			{1, PPME_GENERIC_E, PPME_GENERIC_X},
#endif
#ifdef __NR_old_select 
//	[__NR_old_select] = 	{1, PPME_GENERIC_E, PPME_GENERIC_X},
#endif
#ifdef __NR_pselect6
	[__NR_pselect6] = 		{1, PPME_GENERIC_E, PPME_GENERIC_X},
#endif
#ifdef __NR_epoll_create
	[__NR_epoll_create] =	{1, PPME_GENERIC_E, PPME_GENERIC_X},
#endif
#ifdef __NR_epoll_ctl
	[__NR_epoll_ctl] =		{1, PPME_GENERIC_E, PPME_GENERIC_X},
#endif
#ifdef __NR_uselib
	[__NR_uselib] = 		{1, PPME_GENERIC_E, PPME_GENERIC_X},
#endif
#ifdef __NR_sched_setparam
	[__NR_sched_setparam] = {1, PPME_GENERIC_E, PPME_GENERIC_X},
#endif
#ifdef __NR_sched_getparam
	[__NR_sched_getparam] = {1, PPME_GENERIC_E, PPME_GENERIC_X},
#endif
#ifdef __NR_fork
	[__NR_fork] = 			{1, PPME_GENERIC_E, PPME_GENERIC_X},
#endif
#ifdef __NR_syslog
	[__NR_syslog] = 		{1, PPME_GENERIC_E, PPME_GENERIC_X},
#endif
#ifdef __NR_chmod
	[__NR_chmod] = 			{1, PPME_GENERIC_E, PPME_GENERIC_X},
#endif
#ifdef __NR_lchown
	[__NR_lchown] = 		{1, PPME_GENERIC_E, PPME_GENERIC_X},
#endif
#ifdef __NR_utime
	[__NR_utime] = 			{1, PPME_GENERIC_E, PPME_GENERIC_X},
#endif
#ifdef __NR_mount
	[__NR_mount] = 			{1, PPME_GENERIC_E, PPME_GENERIC_X},
#endif
#ifdef __NR_umount2
	[__NR_umount2] = 		{1, PPME_GENERIC_E, PPME_GENERIC_X},
#endif
#ifdef __NR_setuid
	[__NR_setuid] = 		{1, PPME_GENERIC_E, PPME_GENERIC_X},
#endif
#ifdef __NR_getuid
	[__NR_getuid] = 		{1, PPME_GENERIC_E, PPME_GENERIC_X},
#endif
#ifdef __NR_ptrace
	[__NR_ptrace] = 		{1, PPME_GENERIC_E, PPME_GENERIC_X},
#endif
#ifdef __NR_alarm
	[__NR_alarm] = 			{1, PPME_GENERIC_E, PPME_GENERIC_X},
#endif
#ifdef __NR_pause
	[__NR_pause] = 			{1, PPME_GENERIC_E, PPME_GENERIC_X},
#endif
#ifdef __NR_socket
	[__NR_socket] = 		{1, PPME_SOCKET_SOCKET_E, PPME_SOCKET_SOCKET_X},
#endif
#ifdef __NR_bind
	[__NR_bind] = 			{1, PPME_SOCKET_BIND_E,  PPME_SOCKET_BIND_X},
#endif
#ifdef __NR_connect
	[__NR_connect] = 		{1, PPME_SOCKET_CONNECT_E, PPME_SOCKET_CONNECT_X},
#endif
#ifdef __NR_listen
	[__NR_listen] = 		{1, PPME_SOCKET_LISTEN_E, PPME_SOCKET_LISTEN_X},
#endif
#ifdef __NR_accept
	[__NR_accept] = 		{1, PPME_SOCKET_ACCEPT_E, PPME_SOCKET_ACCEPT_X},
#endif
#ifdef __NR_getsockname
	[__NR_getsockname] = 	{1, PPME_SOCKET_GETSOCKNAME_E, PPME_SOCKET_GETSOCKNAME_X},
#endif
#ifdef __NR_getpeername
	[__NR_getpeername] = 	{1, PPME_SOCKET_GETPEERNAME_E, PPME_SOCKET_GETPEERNAME_X},
#endif
#ifdef __NR_socketpair
	[__NR_socketpair] = 	{1, PPME_SOCKET_SOCKETPAIR_E, PPME_SOCKET_SOCKETPAIR_X},
#endif
#ifdef __NR_sendto
	[__NR_sendto] = 		{1, PPME_SOCKET_SENDTO_E, PPME_SOCKET_SENDTO_X},
#endif
#ifdef __NR_recvfrom
	[__NR_recvfrom] = 		{1, PPME_SOCKET_RECVFROM_E, PPME_SOCKET_RECVFROM_X},
#endif
#ifdef __NR_shutdown
	[__NR_shutdown] = 		{1, PPME_SOCKET_SHUTDOWN_E, PPME_SOCKET_SHUTDOWN_X},
#endif
#ifdef __NR_setsockopt
	[__NR_setsockopt] = 	{1, PPME_SOCKET_SETSOCKOPT_E, PPME_SOCKET_SETSOCKOPT_X},
#endif
#ifdef __NR_getsockopt
	[__NR_getsockopt] = 	{1, PPME_SOCKET_GETSOCKOPT_E, PPME_SOCKET_GETSOCKOPT_X},
#endif
#ifdef __NR_sendmsg
	[__NR_sendmsg] = 		{1, PPME_SOCKET_SENDMSG_E, PPME_SOCKET_SENDMSG_X},
#endif
#ifdef __NR_sendmmsg
	[__NR_sendmmsg] = 		{1, PPME_SOCKET_SENDMMSG_E, PPME_SOCKET_SENDMMSG_X},
#endif
#ifdef __NR_recvmsg
	[__NR_recvmsg] = 		{1, PPME_SOCKET_RECVMSG_E, PPME_SOCKET_RECVMSG_X},
#endif
#ifdef __NR_recvmmsg
	[__NR_recvmmsg] = 		{1, PPME_SOCKET_RECVMMSG_E, PPME_SOCKET_RECVMMSG_X},
#endif
#ifdef __NR_accept4
	[__NR_accept4] = 		{1, PPME_SOCKET_ACCEPT4_E, PPME_SOCKET_ACCEPT4_X},
#endif
#ifdef __NR_stat64
	[__NR_stat64] = 		{1, PPME_SYSCALL_STAT64_E, PPME_SYSCALL_STAT64_X},
#endif
#ifdef __NR_fstat64
	[__NR_fstat64] = 		{1, PPME_SYSCALL_FSTAT64_E, PPME_SYSCALL_FSTAT64_X},
#endif
#ifdef __NR__llseek
	[__NR__llseek] = 		{1, PPME_SYSCALL_LLSEEK_E, PPME_SYSCALL_LLSEEK_X}
#endif
};

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
// SYSCALL ROUTING TABLE
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
const ppm_syscall_code g_syscall_code_routing_table[SYSCALL_TABLE_SIZE] =
{
#ifdef __NR_restart_syscall
	[__NR_restart_syscall] = PPM_SC_RESTART_SYSCALL,
#endif
#ifdef __NR_exit
	[__NR_exit] = PPM_SC_EXIT,
#endif
#ifdef __NR_read
	[__NR_read] = PPM_SC_READ,
#endif
#ifdef __NR_write
	[__NR_write] = PPM_SC_WRITE,
#endif
#ifdef __NR_open
	[__NR_open] = PPM_SC_OPEN,
#endif
#ifdef __NR_close
	[__NR_close] = PPM_SC_CLOSE,
#endif
#ifdef __NR_creat
	[__NR_creat] = PPM_SC_CREAT,
#endif
#ifdef __NR_link
	[__NR_link] = PPM_SC_LINK,
#endif
#ifdef __NR_unlink
	[__NR_unlink] = PPM_SC_UNLINK,
#endif
#ifdef __NR_chdir
	[__NR_chdir] = PPM_SC_CHDIR,
#endif
#ifdef __NR_time
	[__NR_time] = PPM_SC_TIME,
#endif
#ifdef __NR_mknod
	[__NR_mknod] = PPM_SC_MKNOD,
#endif
#ifdef __NR_chmod
	[__NR_chmod] = PPM_SC_CHMOD,
#endif
//	[__NR_lchown16] = PPM_SC_NR_LCHOWN16,
#ifdef __NR_stat
	[__NR_stat] = PPM_SC_STAT,
#endif
#ifdef __NR_lseek
	[__NR_lseek] = PPM_SC_LSEEK,
#endif
#ifdef __NR_getpid
	[__NR_getpid] = PPM_SC_GETPID,
#endif
#ifdef __NR_mount
	[__NR_mount] = PPM_SC_MOUNT,
#endif
//	[__NR_oldumount] = PPM_SC_NR_OLDUMOUNT,
//	[__NR_setuid16] = PPM_SC_NR_SETUID16,
//	[__NR_getuid16] = PPM_SC_NR_GETUID16,
#ifdef __NR_ptrace
	[__NR_ptrace] = PPM_SC_PTRACE,
#endif
#ifdef __NR_alarm
	[__NR_alarm] = PPM_SC_ALARM,
#endif
#ifdef __NR_fstat
	[__NR_fstat] = PPM_SC_FSTAT,
#endif
#ifdef __NR_pause
	[__NR_pause] = PPM_SC_PAUSE,
#endif
#ifdef __NR_utime
	[__NR_utime] = PPM_SC_UTIME,
#endif
#ifdef __NR_access
	[__NR_access] = PPM_SC_ACCESS,
#endif
#ifdef __NR_sync
	[__NR_sync] = PPM_SC_SYNC,
#endif
#ifdef __NR_kill
	[__NR_kill] = PPM_SC_KILL,
#endif
#ifdef __NR_rename
	[__NR_rename] = PPM_SC_RENAME,
#endif
#ifdef __NR_mkdir
	[__NR_mkdir] = PPM_SC_MKDIR,
#endif
#ifdef __NR_rmdir
	[__NR_rmdir] = PPM_SC_RMDIR,
#endif
#ifdef __NR_dup
	[__NR_dup] = PPM_SC_DUP,
#endif
#ifdef __NR_pipe
	[__NR_pipe] = PPM_SC_PIPE,
#endif
#ifdef __NR_times
	[__NR_times] = PPM_SC_TIMES,
#endif
#ifdef __NR_brk
	[__NR_brk] = PPM_SC_BRK,
#endif
//	[__NR_setgid16] = PPM_SC_NR_SETGID16,
//	[__NR_getgid16] = PPM_SC_NR_GETGID16,
//	[__NR_geteuid16] = PPM_SC_NR_GETEUID16,
//	[__NR_getegid16] = PPM_SC_NR_GETEGID16,
#ifdef __NR_acct
	[__NR_acct] = PPM_SC_ACCT,
#endif
#ifdef __NR_ioctl
	[__NR_ioctl] = PPM_SC_IOCTL,
#endif
#ifdef __NR_fcntl
	[__NR_fcntl] = PPM_SC_FCNTL,
#endif
#ifdef __NR_setpgid
	[__NR_setpgid] = PPM_SC_SETPGID,
#endif
#ifdef __NR_umask
	[__NR_umask] = PPM_SC_UMASK,
#endif
#ifdef __NR_chroot
	[__NR_chroot] = PPM_SC_CHROOT,
#endif
#ifdef __NR_ustat
	[__NR_ustat] = PPM_SC_USTAT,
#endif
#ifdef __NR_dup2
	[__NR_dup2] = PPM_SC_DUP2,
#endif
#ifdef __NR_getppid
	[__NR_getppid] = PPM_SC_GETPPID,
#endif
#ifdef __NR_getpgrp
	[__NR_getpgrp] = PPM_SC_GETPGRP,
#endif
#ifdef __NR_setsid
	[__NR_setsid] = PPM_SC_SETSID,
#endif
#ifdef __NR_sethostname
	[__NR_sethostname] = PPM_SC_SETHOSTNAME,
#endif
#ifdef __NR_setrlimit
	[__NR_setrlimit] = PPM_SC_SETRLIMIT,
#endif
//	[__NR_old_getrlimit] = PPM_SC_NR_OLD_GETRLIMIT,
#ifdef __NR_getrusage
	[__NR_getrusage] = PPM_SC_GETRUSAGE,
#endif
#ifdef __NR_gettimeofday
	[__NR_gettimeofday] = PPM_SC_GETTIMEOFDAY,
#endif
#ifdef __NR_settimeofday
	[__NR_settimeofday] = PPM_SC_SETTIMEOFDAY,
#endif
//	[__NR_getgroups16] = PPM_SC_NR_GETGROUPS16,
//	[__NR_setgroups16] = PPM_SC_NR_SETGROUPS16,
//	[__NR_old_select] = PPM_SC_NR_OLD_SELECT,
#ifdef __NR_symlink
	[__NR_symlink] = PPM_SC_SYMLINK,
#endif
#ifdef __NR_lstat
	[__NR_lstat] = PPM_SC_LSTAT,
#endif
#ifdef __NR_readlink
	[__NR_readlink] = PPM_SC_READLINK,
#endif
#ifdef __NR_uselib
	[__NR_uselib] = PPM_SC_USELIB,
#endif
#ifdef __NR_swapon
	[__NR_swapon] = PPM_SC_SWAPON,
#endif
#ifdef __NR_reboot
	[__NR_reboot] = PPM_SC_REBOOT,
#endif
//	[__NR_old_readdir] = PPM_SC_NR_OLD_READDIR,
//	[__NR_old_mmap] = PPM_SC_NR_OLD_MMAP,
#ifdef __NR_mmap
	[__NR_mmap] = PPM_SC_MMAP,
#endif
#ifdef __NR_munmap
	[__NR_munmap] = PPM_SC_MUNMAP,
#endif
#ifdef __NR_truncate
	[__NR_truncate] = PPM_SC_TRUNCATE,
#endif
#ifdef __NR_ftruncate
	[__NR_ftruncate] = PPM_SC_FTRUNCATE,
#endif
#ifdef __NR_fchmod
	[__NR_fchmod] = PPM_SC_FCHMOD,
#endif
//	[__NR_fchown16] = PPM_SC_NR_FCHOWN16,
#ifdef __NR_getpriority
	[__NR_getpriority] = PPM_SC_GETPRIORITY,
#endif
#ifdef __NR_setpriority
	[__NR_setpriority] = PPM_SC_SETPRIORITY,
#endif
#ifdef __NR_statfs
	[__NR_statfs] = PPM_SC_STATFS,
#endif
#ifdef __NR_fstatfs
	[__NR_fstatfs] = PPM_SC_FSTATFS,
#endif
#ifdef __NR_syslog
	[__NR_syslog] = PPM_SC_SYSLOG,
#endif
#ifdef __NR_setitimer
	[__NR_setitimer] = PPM_SC_SETITIMER,
#endif
#ifdef __NR_getitimer
	[__NR_getitimer] = PPM_SC_GETITIMER,
#endif
//	[__NR_newstat] = PPM_SC_NR_NEWSTAT,
//	[__NR_newlstat] = PPM_SC_NR_NEWLSTAT,
//	[__NR_newfstat] = PPM_SC_NR_NEWFSTAT,
#ifdef __NR_uname
	[__NR_uname] = PPM_SC_UNAME,
#endif
#ifdef __NR_vhangup
	[__NR_vhangup] = PPM_SC_VHANGUP,
#endif
#ifdef __NR_wait4
	[__NR_wait4] = PPM_SC_WAIT4,
#endif
#ifdef __NR_swapoff
	[__NR_swapoff] = PPM_SC_SWAPOFF,
#endif
#ifdef __NR_sysinfo
	[__NR_sysinfo] = PPM_SC_SYSINFO,
#endif
#ifdef __NR_fsync
	[__NR_fsync] = PPM_SC_FSYNC,
#endif
#ifdef __NR_setdomainname
	[__NR_setdomainname] = PPM_SC_SETDOMAINNAME,
#endif
//	[__NR_newuname] = PPM_SC_NR_NEWUNAME,
#ifdef __NR_adjtimex
	[__NR_adjtimex] = PPM_SC_ADJTIMEX,
#endif
#ifdef __NR_mprotect
	[__NR_mprotect] = PPM_SC_MPROTECT,
#endif
#ifdef __NR_init_module
	[__NR_init_module] = PPM_SC_INIT_MODULE,
#endif
#ifdef __NR_delete_module
	[__NR_delete_module] = PPM_SC_DELETE_MODULE,
#endif
#ifdef __NR_quotactl
	[__NR_quotactl] = PPM_SC_QUOTACTL,
#endif
#ifdef __NR_getpgid
	[__NR_getpgid] = PPM_SC_GETPGID,
#endif
#ifdef __NR_fchdir
	[__NR_fchdir] = PPM_SC_FCHDIR,
#endif
#ifdef __NR_sysfs
	[__NR_sysfs] = PPM_SC_SYSFS,
#endif
#ifdef __NR_personality
	[__NR_personality] = PPM_SC_PERSONALITY,
#endif
//	[__NR_setfsuid16] = PPM_SC_NR_SETFSUID16,
//	[__NR_setfsgid16] = PPM_SC_NR_SETFSGID16,
//	[__NR_llseek] = PPM_SC_NR_LLSEEK,
#ifdef __NR_getdents
	[__NR_getdents] = PPM_SC_GETDENTS,
#endif
#ifdef __NR_select
	[__NR_select] = PPM_SC_SELECT,
#endif
#ifdef __NR_flock
	[__NR_flock] = PPM_SC_FLOCK,
#endif
#ifdef __NR_msync
	[__NR_msync] = PPM_SC_MSYNC,
#endif
#ifdef __NR_readv
	[__NR_readv] = PPM_SC_READV,
#endif
#ifdef __NR_writev
	[__NR_writev] = PPM_SC_WRITEV,
#endif
#ifdef __NR_getsid
	[__NR_getsid] = PPM_SC_GETSID,
#endif
#ifdef __NR_fdatasync
	[__NR_fdatasync] = PPM_SC_FDATASYNC,
#endif
//	[__NR_sysctl] = PPM_SC_NR_SYSCTL,
#ifdef __NR_mlock
	[__NR_mlock] = PPM_SC_MLOCK,
#endif
#ifdef __NR_munlock
	[__NR_munlock] = PPM_SC_MUNLOCK,
#endif
#ifdef __NR_mlockall
	[__NR_mlockall] = PPM_SC_MLOCKALL,
#endif
#ifdef __NR_munlockall
	[__NR_munlockall] = PPM_SC_MUNLOCKALL,
#endif
#ifdef __NR_sched_setparam
	[__NR_sched_setparam] = PPM_SC_SCHED_SETPARAM,
#endif
#ifdef __NR_sched_getparam
	[__NR_sched_getparam] = PPM_SC_SCHED_GETPARAM,
#endif
#ifdef __NR_sched_setscheduler
	[__NR_sched_setscheduler] = PPM_SC_SCHED_SETSCHEDULER,
#endif
#ifdef __NR_sched_getscheduler
	[__NR_sched_getscheduler] = PPM_SC_SCHED_GETSCHEDULER,
#endif
#ifdef __NR_sched_yield
	[__NR_sched_yield] = PPM_SC_SCHED_YIELD,
#endif
#ifdef __NR_sched_get_priority_max
	[__NR_sched_get_priority_max] = PPM_SC_SCHED_GET_PRIORITY_MAX,
#endif
#ifdef __NR_sched_get_priority_min
	[__NR_sched_get_priority_min] = PPM_SC_SCHED_GET_PRIORITY_MIN,
#endif
#ifdef __NR_sched_rr_get_interval
	[__NR_sched_rr_get_interval] = PPM_SC_SCHED_RR_GET_INTERVAL,
#endif
#ifdef __NR_nanosleep
	[__NR_nanosleep] = PPM_SC_NANOSLEEP,
#endif
#ifdef __NR_mremap
	[__NR_mremap] = PPM_SC_MREMAP,
#endif
//	[__NR_setresuid16] = PPM_SC_NR_SETRESUID16,
//	[__NR_getresuid16] = PPM_SC_NR_GETRESUID16,
#ifdef __NR_poll
	[__NR_poll] = PPM_SC_POLL,
#endif
//	[__NR_setresgid16] = PPM_SC_NR_SETRESGID16,
//	[__NR_getresgid16] = PPM_SC_NR_GETRESGID16,
#ifdef __NR_prctl
	[__NR_prctl] = PPM_SC_PRCTL,
#endif
#ifdef __NR_rt_sigaction
	[__NR_rt_sigaction] = PPM_SC_RT_SIGACTION,
#endif
#ifdef __NR_rt_sigprocmask
	[__NR_rt_sigprocmask] = PPM_SC_RT_SIGPROCMASK,
#endif
#ifdef __NR_rt_sigpending
	[__NR_rt_sigpending] = PPM_SC_RT_SIGPENDING,
#endif
#ifdef __NR_rt_sigtimedwait
	[__NR_rt_sigtimedwait] = PPM_SC_RT_SIGTIMEDWAIT,
#endif
#ifdef __NR_rt_sigqueueinfo
	[__NR_rt_sigqueueinfo] = PPM_SC_RT_SIGQUEUEINFO,
#endif
#ifdef __NR_rt_sigsuspend
	[__NR_rt_sigsuspend] = PPM_SC_RT_SIGSUSPEND,
#endif
//	[__NR_chown16] = PPM_SC_NR_CHOWN16,
#ifdef __NR_getcwd
	[__NR_getcwd] = PPM_SC_GETCWD,
#endif
#ifdef __NR_capget
	[__NR_capget] = PPM_SC_CAPGET,
#endif
#ifdef __NR_capset
	[__NR_capset] = PPM_SC_CAPSET,
#endif
#ifdef __NR_sendfile
	[__NR_sendfile] = PPM_SC_SENDFILE,
#endif
#ifdef __NR_getrlimit
	[__NR_getrlimit] = PPM_SC_GETRLIMIT,
#endif
//	[__NR_mmap_pgoff] = PPM_SC_NR_MMAP_PGOFF,
#ifdef __NR_lchown
	[__NR_lchown] = PPM_SC_LCHOWN,
#endif
#ifdef __NR_getuid
	[__NR_getuid] = PPM_SC_GETUID,
#endif
#ifdef __NR_getgid
	[__NR_getgid] = PPM_SC_GETGID,
#endif
#ifdef __NR_geteuid
	[__NR_geteuid] = PPM_SC_GETEUID,
#endif
#ifdef __NR_getegid
	[__NR_getegid] = PPM_SC_GETEGID,
#endif
#ifdef __NR_setreuid
	[__NR_setreuid] = PPM_SC_SETREUID,
#endif
#ifdef __NR_setregid
	[__NR_setregid] = PPM_SC_SETREGID,
#endif
#ifdef __NR_getgroups
	[__NR_getgroups] = PPM_SC_GETGROUPS,
#endif
#ifdef __NR_setgroups
	[__NR_setgroups] = PPM_SC_SETGROUPS,
#endif
#ifdef __NR_fchown
	[__NR_fchown] = PPM_SC_FCHOWN,
#endif
#ifdef __NR_setresuid
	[__NR_setresuid] = PPM_SC_SETRESUID,
#endif
#ifdef __NR_getresuid
	[__NR_getresuid] = PPM_SC_GETRESUID,
#endif
#ifdef __NR_setresgid
	[__NR_setresgid] = PPM_SC_SETRESGID,
#endif
#ifdef __NR_getresgid
	[__NR_getresgid] = PPM_SC_GETRESGID,
#endif
#ifdef __NR_chown
	[__NR_chown] = PPM_SC_CHOWN,
#endif
#ifdef __NR_setuid
	[__NR_setuid] = PPM_SC_SETUID,
#endif
#ifdef __NR_setgid
	[__NR_setgid] = PPM_SC_SETGID,
#endif
#ifdef __NR_setfsuid
	[__NR_setfsuid] = PPM_SC_SETFSUID,
#endif
#ifdef __NR_setfsgid
	[__NR_setfsgid] = PPM_SC_SETFSGID,
#endif
#ifdef __NR_pivot_root
	[__NR_pivot_root] = PPM_SC_PIVOT_ROOT,
#endif
#ifdef __NR_mincore
	[__NR_mincore] = PPM_SC_MINCORE,
#endif
#ifdef __NR_madvise
	[__NR_madvise] = PPM_SC_MADVISE,
#endif
#ifdef __NR_gettid
	[__NR_gettid] = PPM_SC_GETTID,
#endif
#ifdef __NR_setxattr
	[__NR_setxattr] = PPM_SC_SETXATTR,
#endif
#ifdef __NR_lsetxattr
	[__NR_lsetxattr] = PPM_SC_LSETXATTR, 
#endif
#ifdef __NR_fsetxattr
	[__NR_fsetxattr] = PPM_SC_FSETXATTR,
#endif
#ifdef __NR_getxattr
	[__NR_getxattr] = PPM_SC_GETXATTR,
#endif
#ifdef __NR_lgetxattr
	[__NR_lgetxattr] = PPM_SC_LGETXATTR,
#endif
#ifdef __NR_fgetxattr
	[__NR_fgetxattr] = PPM_SC_FGETXATTR,
#endif
#ifdef __NR_listxattr
	[__NR_listxattr] = PPM_SC_LISTXATTR,
#endif
#ifdef __NR_llistxattr
	[__NR_llistxattr] = PPM_SC_LLISTXATTR,
#endif
#ifdef __NR_flistxattr
	[__NR_flistxattr] = PPM_SC_FLISTXATTR,
#endif
#ifdef __NR_removexattr
	[__NR_removexattr] = PPM_SC_REMOVEXATTR,
#endif
#ifdef __NR_lremovexattr
	[__NR_lremovexattr] = PPM_SC_LREMOVEXATTR,
#endif
#ifdef __NR_fremovexattr
	[__NR_fremovexattr] = PPM_SC_FREMOVEXATTR,
#endif
#ifdef __NR_tkill
	[__NR_tkill] = PPM_SC_TKILL,
#endif
#ifdef __NR_futex
	[__NR_futex] = PPM_SC_FUTEX,
#endif
#ifdef __NR_sched_setaffinity
	[__NR_sched_setaffinity] = PPM_SC_SCHED_SETAFFINITY,
#endif
#ifdef __NR_sched_getaffinity
	[__NR_sched_getaffinity] = PPM_SC_SCHED_GETAFFINITY,
#endif
#ifdef __NR_set_thread_area
	[__NR_set_thread_area] = PPM_SC_SET_THREAD_AREA,
#endif
#ifdef __NR_get_thread_area
	[__NR_get_thread_area] = PPM_SC_GET_THREAD_AREA,
#endif
#ifdef __NR_io_setup
	[__NR_io_setup] = PPM_SC_IO_SETUP,
#endif
#ifdef __NR_io_destroy
	[__NR_io_destroy] = PPM_SC_IO_DESTROY,
#endif
#ifdef __NR_io_getevents
	[__NR_io_getevents] = PPM_SC_IO_GETEVENTS,
#endif
#ifdef __NR_io_submit
	[__NR_io_submit] = PPM_SC_IO_SUBMIT,
#endif
#ifdef __NR_io_cancel
	[__NR_io_cancel] = PPM_SC_IO_CANCEL,
#endif
#ifdef __NR_exit_group
	[__NR_exit_group] = PPM_SC_EXIT_GROUP,
#endif
#ifdef __NR_epoll_create
	[__NR_epoll_create] = PPM_SC_EPOLL_CREATE,
#endif
#ifdef __NR_epoll_ctl
	[__NR_epoll_ctl] = PPM_SC_EPOLL_CTL,
#endif
#ifdef __NR_epoll_wait
	[__NR_epoll_wait] = PPM_SC_EPOLL_WAIT,
#endif
#ifdef __NR_remap_file_pages
	[__NR_remap_file_pages] = PPM_SC_REMAP_FILE_PAGES,
#endif
#ifdef __NR_set_tid_address
	[__NR_set_tid_address] = PPM_SC_SET_TID_ADDRESS,
#endif
#ifdef __NR_timer_create
	[__NR_timer_create] = PPM_SC_TIMER_CREATE,
#endif
#ifdef __NR_timer_settime
	[__NR_timer_settime] = PPM_SC_TIMER_SETTIME,
#endif
#ifdef __NR_timer_gettime
	[__NR_timer_gettime] = PPM_SC_TIMER_GETTIME,
#endif
#ifdef __NR_timer_getoverrun
	[__NR_timer_getoverrun] = PPM_SC_TIMER_GETOVERRUN,
#endif
#ifdef __NR_timer_delete
	[__NR_timer_delete] = PPM_SC_TIMER_DELETE,
#endif
#ifdef __NR_clock_settime
	[__NR_clock_settime] = PPM_SC_CLOCK_SETTIME,
#endif
#ifdef __NR_clock_gettime
	[__NR_clock_gettime] = PPM_SC_CLOCK_GETTIME,
#endif
#ifdef __NR_clock_getres
	[__NR_clock_getres] = PPM_SC_CLOCK_GETRES,
#endif
#ifdef __NR_clock_nanosleep
	[__NR_clock_nanosleep] = PPM_SC_CLOCK_NANOSLEEP,
#endif
#ifdef __NR_tgkill
	[__NR_tgkill] = PPM_SC_TGKILL,
#endif
#ifdef __NR_utimes
	[__NR_utimes] = PPM_SC_UTIMES,
#endif
#ifdef __NR_mq_open
	[__NR_mq_open] = PPM_SC_MQ_OPEN,
#endif
#ifdef __NR_mq_unlink
	[__NR_mq_unlink] = PPM_SC_MQ_UNLINK,
#endif
#ifdef __NR_mq_timedsend
	[__NR_mq_timedsend] = PPM_SC_MQ_TIMEDSEND,
#endif
#ifdef __NR_mq_timedreceive
	[__NR_mq_timedreceive] = PPM_SC_MQ_TIMEDRECEIVE,
#endif
#ifdef __NR_mq_notify
	[__NR_mq_notify] = PPM_SC_MQ_NOTIFY,
#endif
#ifdef __NR_mq_getsetattr
	[__NR_mq_getsetattr] = PPM_SC_MQ_GETSETATTR,
#endif
#ifdef __NR_kexec_load
	[__NR_kexec_load] = PPM_SC_KEXEC_LOAD,
#endif
#ifdef __NR_waitid
	[__NR_waitid] = PPM_SC_WAITID,
#endif
#ifdef __NR_add_key
	[__NR_add_key] = PPM_SC_ADD_KEY,
#endif
#ifdef __NR_request_key
	[__NR_request_key] = PPM_SC_REQUEST_KEY,
#endif
#ifdef __NR_keyctl
	[__NR_keyctl] = PPM_SC_KEYCTL,
#endif
#ifdef __NR_ioprio_set
	[__NR_ioprio_set] = PPM_SC_IOPRIO_SET,
#endif
#ifdef __NR_ioprio_get
	[__NR_ioprio_get] = PPM_SC_IOPRIO_GET,
#endif
#ifdef __NR_inotify_init
	[__NR_inotify_init] = PPM_SC_INOTIFY_INIT,
#endif
#ifdef __NR_inotify_add_watch
	[__NR_inotify_add_watch] = PPM_SC_INOTIFY_ADD_WATCH,
#endif
#ifdef __NR_inotify_rm_watch
	[__NR_inotify_rm_watch] = PPM_SC_INOTIFY_RM_WATCH,
#endif
#ifdef __NR_openat
	[__NR_openat] = PPM_SC_OPENAT,
#endif
#ifdef __NR_mkdirat
	[__NR_mkdirat] = PPM_SC_MKDIRAT,
#endif
#ifdef __NR_mknodat
	[__NR_mknodat] = PPM_SC_MKNODAT,
#endif
#ifdef __NR_fchownat
	[__NR_fchownat] = PPM_SC_FCHOWNAT,
#endif
#ifdef __NR_futimesat
	[__NR_futimesat] = PPM_SC_FUTIMESAT,
#endif
#ifdef __NR_unlinkat
	[__NR_unlinkat] = PPM_SC_UNLINKAT,
#endif
#ifdef __NR_renameat
	[__NR_renameat] = PPM_SC_RENAMEAT,
#endif
#ifdef __NR_linkat
	[__NR_linkat] = PPM_SC_LINKAT,
#endif
#ifdef __NR_symlinkat
	[__NR_symlinkat] = PPM_SC_SYMLINKAT,
#endif
#ifdef __NR_readlinkat
	[__NR_readlinkat] = PPM_SC_READLINKAT,
#endif
#ifdef __NR_fchmodat
	[__NR_fchmodat] = PPM_SC_FCHMODAT,
#endif
#ifdef __NR_faccessat
	[__NR_faccessat] = PPM_SC_FACCESSAT,
#endif
#ifdef __NR_pselect6
	[__NR_pselect6] = PPM_SC_PSELECT6,
#endif
#ifdef __NR_ppoll
	[__NR_ppoll] = PPM_SC_PPOLL,
#endif
#ifdef __NR_unshare
	[__NR_unshare] = PPM_SC_UNSHARE,
#endif
#ifdef __NR_set_robust_list
	[__NR_set_robust_list] = PPM_SC_SET_ROBUST_LIST,
#endif
#ifdef __NR_get_robust_list
	[__NR_get_robust_list] = PPM_SC_GET_ROBUST_LIST,
#endif
#ifdef __NR_splice
	[__NR_splice] = PPM_SC_SPLICE,
#endif
#ifdef __NR_tee
	[__NR_tee] = PPM_SC_TEE,
#endif
#ifdef __NR_vmsplice
	[__NR_vmsplice] = PPM_SC_VMSPLICE,
#endif
#ifdef __NR_getcpu
	[__NR_getcpu] = PPM_SC_GETCPU,
#endif
#ifdef __NR_epoll_pwait
	[__NR_epoll_pwait] = PPM_SC_EPOLL_PWAIT,
#endif
#ifdef __NR_utimensat
	[__NR_utimensat] = PPM_SC_UTIMENSAT,
#endif
#ifdef __NR_signalfd
	[__NR_signalfd] = PPM_SC_SIGNALFD,
#endif
#ifdef __NR_timerfd_create
	[__NR_timerfd_create] = PPM_SC_TIMERFD_CREATE,
#endif
#ifdef __NR_eventfd
	[__NR_eventfd] = PPM_SC_EVENTFD,
#endif
#ifdef __NR_timerfd_settime
	[__NR_timerfd_settime] = PPM_SC_TIMERFD_SETTIME,
#endif
#ifdef __NR_timerfd_gettime
	[__NR_timerfd_gettime] = PPM_SC_TIMERFD_GETTIME,
#endif
#ifdef __NR_signalfd4
	[__NR_signalfd4] = PPM_SC_SIGNALFD4,
#endif
#ifdef __NR_eventfd2
	[__NR_eventfd2] = PPM_SC_EVENTFD2,
#endif
#ifdef __NR_epoll_create1
	[__NR_epoll_create1] = PPM_SC_EPOLL_CREATE1,
#endif
#ifdef __NR_dup3
	[__NR_dup3] = PPM_SC_DUP3,
#endif
#ifdef __NR_pipe2
	[__NR_pipe2] = PPM_SC_PIPE2,
#endif
#ifdef __NR_inotify_init1
	[__NR_inotify_init1] = PPM_SC_INOTIFY_INIT1,
#endif
#ifdef __NR_preadv
	[__NR_preadv] = PPM_SC_PREADV,
#endif
#ifdef __NR_pwritev
	[__NR_pwritev] = PPM_SC_PWRITEV,
#endif
#ifdef __NR_rt_tgsigqueueinfo
	[__NR_rt_tgsigqueueinfo] = PPM_SC_RT_TGSIGQUEUEINFO,
#endif
#ifdef __NR_perf_event_open
	[__NR_perf_event_open] = PPM_SC_PERF_EVENT_OPEN,
#endif
#ifdef __NR_fanotify_init
	[__NR_fanotify_init] = PPM_SC_FANOTIFY_INIT,
#endif
#ifdef __NR_prlimit64
	[__NR_prlimit64] = PPM_SC_PRLIMIT64,
#endif
#ifdef __NR_clock_adjtime
	[__NR_clock_adjtime] = PPM_SC_CLOCK_ADJTIME,
#endif
#ifdef __NR_syncfs
	[__NR_syncfs] = PPM_SC_SYNCFS,
#endif
#ifdef __NR_setns
	[__NR_setns] = PPM_SC_SETNS,
#endif
#ifdef __NR_getdents64
	[__NR_getdents64] =  PPM_SC_GETDENTS64,
#endif
	//
	// Non-multiplexed socket family
	//
#ifdef __NR_socket
	[__NR_socket] =  PPM_SC_SOCKET,
#endif
#ifdef __NR_bind
	[__NR_bind] =  	PPM_SC_BIND,
#endif
#ifdef __NR_connect
	[__NR_connect] =  PPM_SC_CONNECT,
#endif
#ifdef __NR_listen
	[__NR_listen] =  PPM_SC_LISTEN,
#endif
#ifdef __NR_accept
	[__NR_accept] =  PPM_SC_ACCEPT,
#endif
#ifdef __NR_getsockname
	[__NR_getsockname] = PPM_SC_GETSOCKNAME,
#endif
#ifdef __NR_getpeername
	[__NR_getpeername] = PPM_SC_GETPEERNAME,
#endif
#ifdef __NR_socketpair
	[__NR_socketpair] = PPM_SC_SOCKETPAIR,
#endif
//	[__NR_send] =  	PPM_SC_NR_SEND,
#ifdef __NR_sendto
	[__NR_sendto] =  PPM_SC_SENDTO,
#endif
//	[__NR_recv] =  	PPM_SC_NR_RECV,
#ifdef __NR_recvfrom
	[__NR_recvfrom] =  PPM_SC_RECVFROM,
#endif
#ifdef __NR_shutdown
	[__NR_shutdown] =  PPM_SC_SHUTDOWN,
#endif
#ifdef __NR_setsockopt
	[__NR_setsockopt] = PPM_SC_SETSOCKOPT,
#endif
#ifdef __NR_getsockopt
	[__NR_getsockopt] = PPM_SC_GETSOCKOPT,
#endif
#ifdef __NR_sendmsg
	[__NR_sendmsg] =  PPM_SC_SENDMSG,
#endif
#ifdef __NR_sendmmsg
	[__NR_sendmmsg] =  PPM_SC_SENDMMSG,
#endif
#ifdef __NR_recvmsg
	[__NR_recvmsg] =  PPM_SC_RECVMSG,
#endif
#ifdef __NR_recvmmsg
	[__NR_recvmmsg] =  PPM_SC_RECVMMSG,
#endif
#ifdef __NR_accept4
	[__NR_accept4] =  PPM_SC_ACCEPT4,
#endif
	//
	// Non-multiplexed IPC family
	//
#ifdef __NR_semop
	[__NR_semop] =  PPM_SC_SEMOP,
#endif
#ifdef __NR_semget
	[__NR_semget] =  PPM_SC_SEMGET,
#endif
#ifdef __NR_semctl
	[__NR_semctl] =  PPM_SC_SEMCTL,
#endif
#ifdef __NR_msgsnd
	[__NR_msgsnd] =  PPM_SC_MSGSND,
#endif
#ifdef __NR_msgrcv
	[__NR_msgrcv] =  PPM_SC_MSGRCV,
#endif
#ifdef __NR_msgget
	[__NR_msgget] =  PPM_SC_MSGGET,
#endif
#ifdef __NR_msgctl
	[__NR_msgctl] =  PPM_SC_MSGCTL,
#endif
//	[__NR_shmatcall] =  PPM_SC_NR_SHMATCALL,
#ifdef __NR_shmdt
	[__NR_shmdt] =  PPM_SC_SHMDT,
#endif
#ifdef __NR_shmget
	[__NR_shmget] =  PPM_SC_SHMGET,
#endif
#ifdef __NR_shmctl
	[__NR_shmctl] =  PPM_SC_SHMCTL,
#endif
//	[__NR_fcntl64] =  PPM_SC_NR_FCNTL64,
#ifdef __NR_statfs64
	[__NR_statfs64] = PPM_SC_STATFS64,
#endif
#ifdef __NR_fstatfs64
	[__NR_fstatfs64] = PPM_SC_FSTATFS64,
#endif
#ifdef __NR_fstatat64
	[__NR_fstatat64] = PPM_SC_FSTATAT64,
#endif
#ifdef __NR_sendfile64
	[__NR_sendfile64] = PPM_SC_SENDFILE64,
#endif
#ifdef __NR_ugetrlimit
	[__NR_ugetrlimit] = PPM_SC_UGETRLIMIT,
#endif
#ifdef __NR_bdflush
	[__NR_bdflush] = PPM_SC_BDFLUSH,
#endif
#ifdef __NR_sigprocmask
	[__NR_sigprocmask] = PPM_SC_SIGPROCMASK,
#endif
#ifdef __NR_ipc
	[__NR_ipc] = PPM_SC_IPC,
#endif
#ifdef __NR_socketcall
	[__NR_socketcall] = PPM_SC_SOCKETCALL,
#endif
#ifdef __NR_stat64
	[__NR_stat64] = PPM_SC_STAT64,
#endif
#ifdef __NR_lstat64
	[__NR_lstat64] = PPM_SC_LSTAT64,
#endif
#ifdef __NR_fstat64
	[__NR_fstat64] = PPM_SC_FSTAT64,
#endif
#ifdef __NR_fcntl64
	[__NR_fcntl64] = PPM_SC_FCNTL64,
#endif
#ifdef __NR_mmap2
	[__NR_mmap2] = PPM_SC_MMAP2,
#endif
#ifdef __NR__newselect
	[__NR__newselect] = PPM_SC__NEWSELECT,
#endif
#ifdef __NR_sgetmask
	[__NR_sgetmask] = PPM_SC_SGETMASK,
#endif
#ifdef __NR_ssetmask
	[__NR_ssetmask] = PPM_SC_SSETMASK,
#endif
//	[__NR_setreuid16] = PPM_SC_NR_SETREUID16,
//	[__NR_setregid16] = PPM_SC_NR_SETREGID16,
#ifdef __NR_sigpending
	[__NR_sigpending] = PPM_SC_SIGPENDING,
#endif
#ifdef __NR_olduname
	[__NR_olduname] = PPM_SC_OLDUNAME,
#endif
#ifdef __NR_umount
	[__NR_umount] = PPM_SC_UMOUNT,
#endif
#ifdef __NR_signal
	[__NR_signal] = PPM_SC_SIGNAL,
#endif
#ifdef __NR_nice
	[__NR_nice] = PPM_SC_NICE,
#endif
#ifdef __NR_stime
	[__NR_stime] = PPM_SC_STIME,
#endif
#ifdef __NR__llseek
	[__NR__llseek] =	PPM_SC__LLSEEK,
#endif
#ifdef __NR_waitpid
	[__NR_waitpid] = PPM_SC_WAITPID,
#endif
#ifdef __NR_pread64
	[__NR_pread64] = PPM_SC_PREAD64,
#endif
#ifdef __NR_pwrite64
	[__NR_pwrite64] = PPM_SC_PWRITE64,
#endif
};
