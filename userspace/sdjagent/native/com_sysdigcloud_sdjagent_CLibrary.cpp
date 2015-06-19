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

	java_string source_str(env, source);
	java_string destination_str(env, destination);

	pid_t child = fork();

	if(child == 0)
	{
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		char mntnspath[128];
		snprintf(mntnspath, sizeof(mntnspath), "%s/proc/%d/ns/mnt", scap_get_host_root(), pid);

		int fd_from = open(source_str.c_str(), O_RDONLY);
		struct stat from_info = {0};
		fstat(fd_from, &from_info);


		int ns_fd = open(mntnspath, O_RDONLY);
		setns(ns_fd, CLONE_NEWNS);
		close(ns_fd);

		int fd_to = open(destination_str.c_str(), O_WRONLY | O_CREAT, from_info.st_mode);

		int result = sendfile(fd_to, fd_from, NULL, from_info.st_size);

		close(fd_from);
		close(fd_to);
		if(result == from_info.st_size)
		{
			exit(0);
		} else {
			exit(1);
		}
	}
	else
	{
		int status = 0;
		// TODO: avoid blocking?
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
	pipe(child_pipe);

	java_string exe(env, command);

	snprintf(nspath, sizeof(nspath), "%s/proc/%d/ns/pid", scap_get_host_root(), pid);
	int pidnsfd = open(nspath, O_RDONLY);

	snprintf(nspath, sizeof(nspath), "%s/proc/self/ns/pid", scap_get_host_root());
	int mypidnsfd = open(nspath, O_RDONLY);

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

	setns(pidnsfd, CLONE_NEWPID);
	close(pidnsfd);
	pid_t child = fork();

	if(child == 0)
	{
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		dup2(child_pipe[1], STDOUT_FILENO);

		snprintf(nspath, sizeof(nspath), "%s/proc/%d/ns/mnt", scap_get_host_root(), pid);
		int mntnsfd = open(nspath, O_RDONLY);
		snprintf(nspath, sizeof(nspath), "%s/proc/%d/ns/net", scap_get_host_root(), pid);
		int netnsfd = open(nspath, O_RDONLY);
		snprintf(nspath, sizeof(nspath), "%s/proc/%d/ns/user", scap_get_host_root(), pid);
		int usernsfd = open(nspath, O_RDONLY);
		snprintf(nspath, sizeof(nspath), "%s/proc/%d/ns/uts", scap_get_host_root(), pid);
		int utsnsfd = open(nspath, O_RDONLY);
		snprintf(nspath, sizeof(nspath), "%s/proc/%d/ns/ipc", scap_get_host_root(), pid);
		int ipcnsfd = open(nspath, O_RDONLY);

		setns(netnsfd, CLONE_NEWNET);
		close(netnsfd);
		setns(utsnsfd, CLONE_NEWUTS);
		close(utsnsfd);
		setns(ipcnsfd, CLONE_NEWIPC);
		close(ipcnsfd);
		setns(mntnsfd, CLONE_NEWNS);
		close(mntnsfd);
		setns(usernsfd, CLONE_NEWUSER);
		close(usernsfd);

		execv(exe.c_str(), (char* const*)command_args_c);
	}
	else
	{
		setns(mypidnsfd, CLONE_NEWPID);
		close(mypidnsfd);

		int status = 0;
		// TODO: avoid blocking?
		waitpid(child, &status, 0);
		FILE* output = fdopen(child_pipe[0], "r");
		char output_buffer[1024];
		fgets(output_buffer, sizeof(output_buffer), output);
		ret = env->NewStringUTF(output_buffer);
	}
	return ret;
}

JNIEXPORT jint JNICALL Java_com_sysdigcloud_sdjagent_CLibrary_realRmFromContainer
		(JNIEnv* env, jclass, jint pid, jstring path)
{
	int res = 1;

	java_string path_str(env, path);

	pid_t child = fork();

	if(child == 0)
	{
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		char mntnspath[128];
		snprintf(mntnspath, sizeof(mntnspath), "%s/proc/%d/ns/mnt", scap_get_host_root(), pid);

		int ns_fd = open(mntnspath, O_RDONLY);
		setns(ns_fd, CLONE_NEWNS);
		close(ns_fd);

		int res = remove(path_str.c_str());

		if(res == 0)
		{
			exit(0);
		} else {
			exit(1);
		}
	}
	else
	{
		int status = 0;
		// TODO: avoid blocking?
		waitpid(child, &status, 0);
		if(WIFEXITED(status))
		{
			res = WEXITSTATUS(status);
		}
	}

	return res;
}