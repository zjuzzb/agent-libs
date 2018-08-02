//
// Created by Luca Marturana on 19/05/16.
//
#pragma once

#include <jni.h>
#include <stdint.h>
#include <unistd.h>

// Wraps the conversion between a jstring and a const char*
class java_string
{
public:
	explicit java_string(JNIEnv* env, jstring java_s)
	{
		m_java_ptr = java_s;
		m_env = env;
		m_c_str = m_env->GetStringUTFChars(m_java_ptr, NULL);
	}

	~java_string()
	{
		if(m_c_str != NULL)
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
		m_env = other.m_env;
		m_java_ptr = other.m_java_ptr;

		other.m_c_str = NULL;
		other.m_env = NULL;
		other.m_java_ptr = NULL;
	}

	java_string& operator=(java_string&& other)
	{
		m_c_str = other.m_c_str;
		m_env = other.m_env;
		m_java_ptr = other.m_java_ptr;

		other.m_c_str = NULL;
		other.m_env = NULL;
		other.m_java_ptr = NULL;
		return *this;
	}

	uint64_t size()
	{
		return m_env->GetStringLength(m_java_ptr);
	}

private:
	const char* m_c_str;
	JNIEnv* m_env;
	jstring m_java_ptr;
};

template<typename... Args>
void log(const char* sev, const char* msgfmt, Args... args)
{
	static const char* logfmt = "{\"pid\": %d, \"level\": \"%s\", \"message\": \"%s\" }\n";
	static const size_t buffer_size = 500;
	char msg[buffer_size];
	snprintf(msg, buffer_size, msgfmt, args...);
	fprintf(stderr, logfmt, getpid(), sev, msg);
	fflush(stderr);
}