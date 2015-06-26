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

using namespace std;

// Wraps the conversion between a jstring and a const char*
class java_string
{
public:
	explicit java_string(JNIEnv* env, jstring java_s)
	{
		m_java_ptr = java_s;
		m_env = env;
		m_is_copy = JNI_FALSE;
		m_c_str = m_env->GetStringUTFChars(m_java_ptr, &m_is_copy);
	}

	~java_string()
	{
		if(m_c_str != NULL && m_is_copy == JNI_TRUE)
		{
			m_env->ReleaseStringUTFChars(m_java_ptr, m_c_str);
		}
	}

	const char* c_str() const {
		return m_c_str;
	}

	// Deny copying of this object
	java_string(const java_string&) = delete;
	java_string& operator=(const java_string&) = delete;

	// Allow moving
	java_string(java_string&& other)
	{
		m_c_str = other.m_c_str;
		m_is_copy = other.m_is_copy;
		m_env = other.m_env;
		m_java_ptr = other.m_java_ptr;

		other.m_c_str = NULL;
		other.m_is_copy = JNI_FALSE;
		other.m_env = NULL;
		other.m_java_ptr = NULL;
	}

	java_string& operator=(java_string&& other)
	{
		m_c_str = other.m_c_str;
		m_is_copy = other.m_is_copy;
		m_env = other.m_env;
		m_java_ptr = other.m_java_ptr;

		other.m_c_str = NULL;
		other.m_is_copy = JNI_FALSE;
		other.m_env = NULL;
		other.m_java_ptr = NULL;
		return *this;
	}

private:
	const char* m_c_str;
	jboolean m_is_copy;
	JNIEnv* m_env;
	jstring m_java_ptr;
};

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
	const char* p = getenv("SYSDIG_HOST_ROOT");
	if(!p)
	{
		p = "";
	}
	return p;
}

// Use raw setns syscall for versions of glibc that don't include it (namely glibc-2.12)
#if __GLIBC__ == 2 && __GLIBC_MINOR__ < 14
#define _GNU_SOURCE
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
			exit(0);
		}
		else
		{
			exit(1);
		}
	}
	else
	{
		int status = 0;
		waitpid(child, &status, 0);
		if(WIFEXITED(status))
		{
			res = WEXITSTATUS(status);
		}
	}

	return res;
}

JNIEXPORT jstring JNICALL Java_com_sysdigcloud_sdjagent_CLibrary_realRunOnContainer
		(JNIEnv* env, jclass, jint pid, jstring command, jobjectArray commandArgs)
{
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

	setns(pidnsfd.fd(), CLONE_NEWPID);
	pid_t child = fork();

	if(child == 0)
	{
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		dup2(child_pipe[1], STDOUT_FILENO);

		// Copy environment of the target process
		const char* container_environ_ptr[100];
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
		int j = 0;
		for(const auto& env : container_environ)
		{
			container_environ_ptr[j++] = env.c_str();
		}
		container_environ_ptr[j++] = NULL;
		environ_file.close();

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

		execve(exe.c_str(), (char* const*)command_args_c, (char* const*) container_environ_ptr);
	}
	else
	{
		int status = 0;
		waitpid(child, &status, 0);
		setns(mypidnsfd.fd(), CLONE_NEWPID);

		FILE* output = fdopen(child_pipe[0], "r");
		char output_buffer[1024];
		if(fgets(output_buffer, sizeof(output_buffer), output) == output_buffer)
		{
			ret = env->NewStringUTF(output_buffer);
		}
	}
	return ret;
}

JNIEXPORT jint JNICALL Java_com_sysdigcloud_sdjagent_CLibrary_realRmFromContainer
		(JNIEnv* env, jclass, jint pid, jstring path)
{
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
		int status = 0;
		waitpid(child, &status, 0);
		if(WIFEXITED(status))
		{
			res = WEXITSTATUS(status);
		}
	}

	return res;
}