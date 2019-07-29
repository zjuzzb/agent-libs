#pragma once

#include <event.h>
#include <cstdlib> // for rand
#include <functional>

namespace test_helpers
{

/**
 * Easy way to create threadinfo in unit test. The constructor sets defaults
 * for all of the events values and this class has setters for the other
 * values.  Each setter returns *this so that the setters can be called in
 * sequence.
 *
 * Since the sysdig classes expect a raw pointer, this class returns a raw
 * pointer instead of a smart pointer and it is the responsibility of the
 * caller to manage the lifetime of the class.
 *
 * This is meant to be constructed by a test_helper that set the commit
 * delegate before passing the thread_builder back to the client.
 *
 * Usage: thread_builder().pid(10).name("top").commit()
 */
class thread_builder
{
public:

	/**
	 * ctor without commit
	 */
//	thread_builder() :
//	   m_threadinfo(new sinsp_threadinfo())
//	{
//		set_defaults();
//	}

	using commit_delegate = std::function<void(sinsp_threadinfo *thread_info)>;
	/**
	 * ctor with a commit delegate where the generated events are
	 * sent to a consumer.
	 */
	thread_builder(const commit_delegate& delegate) :
	   m_commit(delegate),
	   m_threadinfo(new sinsp_threadinfo())
	{
		set_defaults();
	}

	/**
	 * Set the pid
	 */
	thread_builder& pid(int64_t value)
	{
		m_threadinfo->m_pid = value;
		if (0 == m_threadinfo->m_tid)
		{
			m_threadinfo->m_tid = value;
		}
		return *this;
	}

	/**
	 * Set the tid
	 */
	thread_builder& tid(int64_t value)
	{
		m_threadinfo->m_tid = value;
		if (0 == m_threadinfo->m_pid)
		{
			m_threadinfo->m_pid = value;
		}
		return *this;
	}

	/**
	 * Set the command
	 */
	thread_builder& comm(const std::string &value)
	{
		m_threadinfo->m_comm = value;
		return *this;
	}

	/**
	 * Set the exe
	 */
	thread_builder& exe(const std::string& value)
	{
		m_threadinfo->m_exe = value;
		return *this;
	}

	/**
	 * Add an argument
	 */
	thread_builder& arg(const std::string &value)
	{
		m_threadinfo->m_args.push_back(value);
		return *this;
	}


	/**
	 * Fill any empty fields with data
	 */
	void fill_empty_fields()
	{
		if (0 == m_threadinfo->m_pid)
		{
			m_threadinfo->m_pid = m_threadinfo->m_tid = rand();
		}
		if (m_threadinfo->m_comm.empty())
		{
			m_threadinfo->m_comm = "default_command";
		}
	}

	/**
	 * Complete the threadinfo and pass it to the consumer
	 */
	const sinsp_threadinfo* commit()
	{
		fill_empty_fields();
		m_commit(m_threadinfo);
		return m_threadinfo;
	}
private:

	void set_defaults()
	{
		m_threadinfo->m_pid = 0;
		m_threadinfo->m_tid = 0;
	}

	commit_delegate m_commit;
	sinsp_threadinfo *m_threadinfo;

};

}
