/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class com_sysdigcloud_sdjagent_PosixQueue */

#ifndef _Included_com_sysdigcloud_sdjagent_PosixQueue
#define _Included_com_sysdigcloud_sdjagent_PosixQueue
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     com_sysdigcloud_sdjagent_PosixQueue
 * Method:    setQueueLimits
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_com_sysdigcloud_sdjagent_PosixQueue_setQueueLimits
  (JNIEnv *, jclass);

/*
 * Class:     com_sysdigcloud_sdjagent_PosixQueue
 * Method:    openQueue
 * Signature: (Ljava/lang/String;II)I
 */
JNIEXPORT jint JNICALL Java_com_sysdigcloud_sdjagent_PosixQueue_openQueue
  (JNIEnv *, jclass, jstring, jint, jint);

/*
 * Class:     com_sysdigcloud_sdjagent_PosixQueue
 * Method:    queueSend
 * Signature: (ILjava/lang/String;)Z
 */
JNIEXPORT jint JNICALL Java_com_sysdigcloud_sdjagent_PosixQueue_queueSend
  (JNIEnv *, jclass, jint, jstring);

/*
 * Class:     com_sysdigcloud_sdjagent_PosixQueue
 * Method:    queueReceive
 * Signature: (IJ)Ljava/lang/String;
 */
JNIEXPORT jint JNICALL Java_com_sysdigcloud_sdjagent_PosixQueue_queueReceive
  (JNIEnv *, jclass, jint, jbyteArray, jlong);

/*
 * Class:     com_sysdigcloud_sdjagent_PosixQueue
 * Method:    queueClose
 * Signature: (I)Z
 */
JNIEXPORT jboolean JNICALL Java_com_sysdigcloud_sdjagent_PosixQueue_queueClose
  (JNIEnv *, jclass, jint);

#ifdef __cplusplus
}
#endif
#endif
