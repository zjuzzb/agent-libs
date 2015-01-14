#include "com_sysdigcloud_sdjagent_CLibrary.h"
#include <unistd.h>

JNIEXPORT jint JNICALL Java_com_sysdigcloud_sdjagent_CLibrary_real_1seteuid
        (JNIEnv *, jclass, jlong euid)
{
    return seteuid(euid);
}

JNIEXPORT jint JNICALL Java_com_sysdigcloud_sdjagent_CLibrary_real_1setegid
        (JNIEnv *, jclass, jlong egid)
{
    return setegid(egid);
}