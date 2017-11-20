#include "com_sysdigcloud_sdjagent_CLibrary.h"

#include <unistd.h>
#include <sys/prctl.h>
#include <signal.h>
#include <stdlib.h>
#include <sched.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <sys/wait.h>
#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include <signal.h>
#include <string.h>

#include "jni_utils.h"

using namespace std;

class file_descriptor
{
public:
	explicit file_descriptor(const char* path, int flags)
	{
		m_fd = open(path, flags);
	}

	explicit file_descriptor(const char* path, int flags, mode_t mode)
	{
		m_fd = open(path, flags, mode);
	}

	~file_descriptor()
	{
		if(is_valid())
		{
			close(m_fd);
		}
	}

	int fd()
	{
		return m_fd;
	}

	bool is_valid()
	{
		return m_fd >= 0;
	}

	// Deny copying of this object
	file_descriptor(const file_descriptor&) = delete;
	file_descriptor& operator=(const file_descriptor&) = delete;

private:
	int m_fd;
};

// Function imported from scap, to link scap it should be compiled with -fPIC and it's not
const char* scap_get_host_root()
{
	static const char* p = getenv("SYSDIG_HOST_ROOT");
	static const auto str = (p) ? p : "";

	// limit the length of the string to SCAP_MAX_PATH_SIZE defined in scap.h
	static const size_t SCAP_MAX_PATH_SIZE = 1024;
	static const std::string env_str(str, strnlen(str, SCAP_MAX_PATH_SIZE));

	return env_str.c_str();
}

//
// Returns status code of exited process or -1 if it did not exit in specified timeout
//

class timed_waitpid final
{
public:
	explicit timed_waitpid()
	{
		// Block child signal, so we can use sigtimedwait()
		sigset_t mask;
		sigemptyset (&mask);
		sigaddset (&mask, SIGCHLD);

		sigprocmask(SIG_BLOCK, &mask, &m_orig_set);
	}
	~timed_waitpid()
	{
		// Restore previous sigmask
		sigprocmask(SIG_SETMASK, &m_orig_set, NULL);
	}

	int wait(pid_t pid, unsigned timeout_s=20)
	{
		sigset_t mask;
		sigemptyset(&mask);
		sigaddset(&mask, SIGCHLD);

		struct timespec timeout;
		timeout.tv_sec = timeout_s;
		timeout.tv_nsec = 0;

		sigtimedwait(&mask, NULL, &timeout);

		int status = 0;
		int wait_res = waitpid(pid, &status, WNOHANG);

		if(wait_res > 0 && WIFEXITED(status))
		{
			return WEXITSTATUS(status);
		}
		return -1;
	}

	timed_waitpid(const timed_waitpid&) = delete;
	timed_waitpid& operator=(const timed_waitpid&) = delete;
private:
	sigset_t m_orig_set;
};

// Use raw setns syscall for versions of glibc that don't include it (namely glibc-2.12)
#if __GLIBC__ == 2 && __GLIBC_MINOR__ < 14
//#define _GNU_SOURCE
#include "syscall.h"
#if defined(__NR_setns) && !defined(SYS_setns)
#define SYS_setns __NR_setns
#endif
#ifdef SYS_setns
int setns(int fd, int nstype)
{
	return syscall(SYS_setns, fd, nstype);
}
#endif
#endif

JNIEXPORT jint JNICALL Java_com_sysdigcloud_sdjagent_CLibrary_real_1seteuid
        (JNIEnv *, jclass, jlong euid)
{
	int res = seteuid(euid);
	// We need to call again prctl() because PDEATHSIG is cleared
	// after seteuid call
	prctl(PR_SET_PDEATHSIG, SIGKILL);
	return res;
}

JNIEXPORT jint JNICALL Java_com_sysdigcloud_sdjagent_CLibrary_real_1setegid
        (JNIEnv *, jclass, jlong egid)
{
	int res = setegid(egid);
	// We need to call again prctl() because PDEATHSIG is cleared
	// after setegid call
	prctl(PR_SET_PDEATHSIG, SIGKILL);
	return res;
}

JNIEXPORT jint JNICALL Java_com_sysdigcloud_sdjagent_CLibrary_real_1setenv
        (JNIEnv * env, jclass, jstring name, jstring value, jint overwrite)
{
	java_string name_c(env, name);
	java_string value_c(env, value);
	int res = setenv(name_c.c_str(), value_c.c_str(), overwrite);
	return res;
}

JNIEXPORT jint JNICALL Java_com_sysdigcloud_sdjagent_CLibrary_real_1unsetenv
        (JNIEnv* env, jclass, jstring name)
{
	java_string name_c(env, name);
	int res = unsetenv(name_c.c_str());
	return res;
}

JNIEXPORT jint JNICALL Java_com_sysdigcloud_sdjagent_CLibrary_setns
		(JNIEnv *, jclass, jint fd, jint type)
{
	return setns(fd, type);
}

JNIEXPORT jint JNICALL Java_com_sysdigcloud_sdjagent_CLibrary_open_1fd
		(JNIEnv* env, jclass, jstring path)
{
	java_string path_c(env,path);
	int res = open(path_c.c_str(), O_RDONLY);
	return res;
}

JNIEXPORT jint JNICALL Java_com_sysdigcloud_sdjagent_CLibrary_close_1fd
		(JNIEnv *, jclass, jint fd)
{
	return close(fd);
}

JNIEXPORT jint JNICALL Java_com_sysdigcloud_sdjagent_CLibrary_realCopyToContainer
		(JNIEnv* env, jclass, jstring source, jint pid, jstring destination)
{
	timed_waitpid wait_pid;
	int res = 1;

	// Open here the namespace so we are sure that the process is live before forking
	char mntnspath[128];
	snprintf(mntnspath, sizeof(mntnspath), "%s/proc/%d/ns/mnt", scap_get_host_root(), pid);
	file_descriptor ns_fd(mntnspath, O_RDONLY);
	if(!ns_fd.is_valid())
	{
		return res;
	}

	java_string source_str(env, source);
	java_string destination_str(env, destination);

	pid_t child = fork();

	if(child == 0)
	{
		prctl(PR_SET_PDEATHSIG, SIGKILL);

		file_descriptor fd_from(source_str.c_str(), O_RDONLY);
		if(!fd_from.is_valid())
		{
			exit(1);
		}

		struct stat from_info = {0};
		fstat(fd_from.fd(), &from_info);

		setns(ns_fd.fd(), CLONE_NEWNS);

		file_descriptor fd_to(destination_str.c_str(), O_WRONLY | O_CREAT, from_info.st_mode);
		if(!fd_to.is_valid())
		{
			exit(1);
		}

		int result = sendfile(fd_to.fd(), fd_from.fd(), NULL, from_info.st_size);

		if(result == from_info.st_size)
		{
			// We need it readable by everyone, because
			// inside containers we run our sdjagent with
			// uid=uid_of_target_jvm
			if(fchmod(fd_to.fd(), S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH) != 0)
			{
				log("SEVERE", "Cannot change permissions of %s", destination_str.c_str());
			}
			exit(0);
		}
		else
		{
			exit(1);
		}
	}
	else
	{
		auto wait_res = wait_pid.wait(child);
		if(wait_res >= 0)
		{
			res = wait_res;
		}
		else
		{
			kill(child, SIGKILL);
			waitpid(child, NULL, 0);
		}
	}

	return res;
}

JNIEXPORT jstring JNICALL Java_com_sysdigcloud_sdjagent_CLibrary_realRunOnContainer
		(JNIEnv* env, jclass, jint pid, jint vpid, jstring command, jobjectArray commandArgs, jstring root)
{
	timed_waitpid wait_pid;

	int child_pipe[2];
	char nspath[128];
	jstring ret = NULL;
	if(pipe(child_pipe) != 0)
	{
		return ret;
	}

	java_string exe(env, command);

	snprintf(nspath, sizeof(nspath), "%s/proc/%d/ns/pid", scap_get_host_root(), pid);
	file_descriptor pidnsfd(nspath, O_RDONLY);

	if(!pidnsfd.is_valid())
	{
		return ret;
	}

	snprintf(nspath, sizeof(nspath), "%s/proc/self/ns/pid", scap_get_host_root());
	file_descriptor mypidnsfd(nspath, O_RDONLY);

	if(!pidnsfd.is_valid())
	{
		return ret;
	}

	// Build command line for execv
	vector<java_string> command_args;
	const char* command_args_c[30];
	for(int j = 0; j < env->GetArrayLength(commandArgs); ++j)
	{
		jstring arg = (jstring) env->GetObjectArrayElement(commandArgs, j);
		command_args.emplace_back(env, arg);
	}
	int j = 0;
	for(const auto& arg : command_args)
	{
		command_args_c[j++] = arg.c_str();
	}
	command_args_c[j++] = NULL;

	java_string root_s(env, root);

	setns(pidnsfd.fd(), CLONE_NEWPID);
	pid_t child = fork();

	if(child == 0)
	{
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		dup2(child_pipe[1], STDOUT_FILENO);
		close(child_pipe[0]);

		// Copy environment of the target process
		vector<string> container_environ;
		char environ_path[200];
		snprintf(environ_path, sizeof(environ_path), "%s/proc/%d/environ", scap_get_host_root(), pid);
		ifstream environ_file(environ_path);
		while(environ_file.good())
		{
			string read_buffer;
			std::getline( environ_file, read_buffer, '\0' );
			if(!read_buffer.empty())
			{
				container_environ.push_back(move(read_buffer));
			}
		}
		environ_file.close();

		const char** container_environ_ptr = (const char**) malloc(sizeof(char*)*(container_environ.size()+1));
		int j = 0;
		for(const auto& env : container_environ)
		{
			container_environ_ptr[j++] = env.c_str();
		}
		container_environ_ptr[j++] = NULL;


		// Open namespaces of target process
		snprintf(nspath, sizeof(nspath), "%s/proc/%d/ns/mnt", scap_get_host_root(), pid);
		file_descriptor mntnsfd(nspath, O_RDONLY);
		snprintf(nspath, sizeof(nspath), "%s/proc/%d/ns/net", scap_get_host_root(), pid);
		file_descriptor netnsfd(nspath, O_RDONLY);
		snprintf(nspath, sizeof(nspath), "%s/proc/%d/ns/user", scap_get_host_root(), pid);
		file_descriptor usernsfd(nspath, O_RDONLY);
		snprintf(nspath, sizeof(nspath), "%s/proc/%d/ns/uts", scap_get_host_root(), pid);
		file_descriptor utsnsfd(nspath, O_RDONLY);
		snprintf(nspath, sizeof(nspath), "%s/proc/%d/ns/ipc", scap_get_host_root(), pid);
		file_descriptor ipcnsfd(nspath, O_RDONLY);

		setns(netnsfd.fd(), CLONE_NEWNET);
		setns(utsnsfd.fd(), CLONE_NEWUTS);
		setns(ipcnsfd.fd(), CLONE_NEWIPC);
		setns(mntnsfd.fd(), CLONE_NEWNS);
		setns(usernsfd.fd(), CLONE_NEWUSER);

		// read uid and gid of target process
		char proc_status_path[200];
		snprintf(proc_status_path, sizeof(proc_status_path), "/proc/%d/status", vpid);
		ifstream proc_status(proc_status_path);
		uid_t uid = 0;
		gid_t gid = 0;

		while(proc_status.good())
		{
			string read_buffer;
			std::getline(proc_status, read_buffer);
			if(read_buffer.find("Uid:") == 0)
			{
				sscanf(read_buffer.c_str(), "%*s %u", &uid);
				std::getline(proc_status, read_buffer);
				sscanf(read_buffer.c_str(), "%*s %u", &gid);
				break;
			}
		}
		proc_status.close();
		log("FINE", "Read uid=%d and gid=%d of target process", uid, gid);

		// set process root
		if(strncmp(root_s.c_str(), "/", 2) != 0)
		{
			auto ret = chroot(root_s.c_str());
			if(ret != 0)
			{
				log("SEVERE", "Cannot chroot inside container, errno=%s", strerror(errno));
				exit(1);
			}
			chdir("/");
		}

		if(setgid(gid) != 0)
		{
			log("SEVERE", "setgid failed errno=%s", strerror(errno));
			exit(1);
		}
		if(setuid(uid) != 0)
		{
			log("SEVERE", "setuid failed errno=%s", strerror(errno));
			exit(1);
		}
		prctl(PR_SET_PDEATHSIG, SIGKILL);

		execve(exe.c_str(), (char* const*)command_args_c, (char* const*) container_environ_ptr);
		free(container_environ_ptr);
		log("SEVERE", "Cannot exec sdjagent inside container, errno=%s", strerror(errno));
		exit(1);
	}
	else
	{
		close(child_pipe[1]);
		setns(mypidnsfd.fd(), CLONE_NEWPID);

		auto wait_res = wait_pid.wait(child);
		if(wait_res == 0)
		{
			// The process ended correctly, read the result
			FILE* output = fdopen(child_pipe[0], "r");
			char output_buffer[1024];
			if(fgets(output_buffer, sizeof(output_buffer), output) == output_buffer)
			{
				ret = env->NewStringUTF(output_buffer);
			}
			fclose(output);
		}
		else
		{
			// The process didn't end correctly,
			// just cleanup resources
			close(child_pipe[0]);
			if (wait_res < 0)
			{
				// The process didn't end within the wait timeout
				// kill and reap it
				kill(child, SIGKILL);
				waitpid(child, NULL, 0);
			}
		}
	}
	return ret;
}

JNIEXPORT jint JNICALL Java_com_sysdigcloud_sdjagent_CLibrary_realRmFromContainer
		(JNIEnv* env, jclass, jint pid, jstring path)
{
	timed_waitpid wait_pid;
	int res = 1;

	char mntnspath[128];
	snprintf(mntnspath, sizeof(mntnspath), "%s/proc/%d/ns/mnt", scap_get_host_root(), pid);

	file_descriptor ns_fd(mntnspath, O_RDONLY);
	if(!ns_fd.is_valid())
	{
		return res;
	}

	java_string path_str(env, path);

	pid_t child = fork();

	if(child == 0)
	{
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		setns(ns_fd.fd(), CLONE_NEWNS);

		int res = remove(path_str.c_str());

		if(res == 0)
		{
			exit(0);
		}
		else
		{
			exit(1);
		}
	}
	else
	{
		auto wait_res = wait_pid.wait(child);
		if(wait_res >= 0)
		{
			res = wait_res;
		}
		else
		{
			kill(child, SIGKILL);
			waitpid(child, NULL, 0);
		}
	}

	return res;
}

JNIEXPORT jlong JNICALL Java_com_sysdigcloud_sdjagent_CLibrary_getInodeOfFile
		(JNIEnv* env, jclass, jstring path)
{
	java_string path_s(env, path);
	struct stat buf;
	int ret = stat(path_s.c_str(), &buf);
	if (ret == 0)
	{
		return buf.st_ino;
	}
	else
	{
		return 0;
	}
}
