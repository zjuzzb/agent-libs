#include "com_sysdigcloud_sdjagent_CLibrary.h"
#include <unistd.h>
#include <sys/prctl.h>
#include <signal.h>

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