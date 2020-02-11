#pragma once

#include <assert.h>
#include <cstdlib>  // for rand
#include <event.h>
#include <functional>
#include "sinsp.h"

namespace test_helpers
{
/**
 * Easy way to create sinsp_threadinfo in unit test. Setters are provided
 * for many fields and the class (should) create defaults for any mandatory
 * fields that the client does explicitly set. Each setter returns *this so
 * that the setters can be called in sequence.
 *
 * The built value can be used in two ways:
 * 1. via the commit function to pass ownership to a separate class and
 *    return a reference:
 *    example: auto &tinfo = mock.build_thread().exe("sysdig").commit()
 * 2. via the release function to pass ownership to the caller:
 *    example: auto tinfo = thread_builder().pid(10).name("top").release()
 *
 * Usually with this pattern, the class would return a shared_ptr but this
 * was designed to work with code that uses raw pointers.
 */
class thread_builder
{
public:
	using mutable_threadinfo_ptr_t = std::shared_ptr<sinsp_threadinfo>;
	using commit_delegate = std::function<void(sinsp_threadinfo* thread_info)>;
	/**
	 * ctor with a commit delegate where the generated events are
	 * sent to a consumer.
	 */
	thread_builder(sinsp* inspector, const commit_delegate& delegate)
	    : m_commit(delegate),
	      m_threadinfo(inspector->build_threadinfo())
	{
		set_defaults();
	}

	/**
	 * ctor without commit.
	 */
	thread_builder() : m_threadinfo(new sinsp_threadinfo()) { set_defaults(); }

	~thread_builder()
	{
		if (m_threadinfo)
		{
			assert(!"This shouldn't happen if you are using this "
				"class correctly. Either call commit or release "
				"before the builder is destroyed.");
		}
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
	thread_builder& comm(const std::string& value)
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
	thread_builder& arg(const std::string& value)
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
			// Because of how the mutators work, if the pid is
			// zero then the tid is also empty. Set them both to
			// a random value.
			m_threadinfo->m_pid = m_threadinfo->m_tid = rand();
		}
		if (m_threadinfo->m_comm.empty())
		{
			m_threadinfo->m_comm = "default_command";
		}
	}

	/**
	 * Complete the threadinfo and pass ownership to the consumer. Pass a
	 * non-owning reference back to the client.
	 */
	sinsp_threadinfo& commit()
	{
		fill_empty_fields();
		m_commit(m_threadinfo);

		// The commit function passed ownership to the consumer so here
		// we release from this class and return a ref.
		return *release_ptr();
	}

	/**
	 * Pass ownership back to the caller.
	 */
	std::unique_ptr<sinsp_threadinfo> release()
	{
		return std::unique_ptr<sinsp_threadinfo>(release_ptr());
	}

private:
	/**
	 * This class stores a raw_ptr copy of the data. This function clears
	 * ownership from this class (so that it won't be deleted) and returns the
	 * raw pointer.
	 */
	sinsp_threadinfo* release_ptr()
	{
		sinsp_threadinfo* temp = m_threadinfo;
		m_threadinfo = nullptr;
		return temp;
	}

	void set_defaults()
	{
		m_threadinfo->m_pid = 0;
		m_threadinfo->m_tid = 0;
		m_threadinfo->m_uid = rand();
		m_threadinfo->m_clone_ts = sinsp_utils::get_current_time_ns() - 1000000;
	}

	commit_delegate m_commit;
	sinsp_threadinfo* m_threadinfo;
};

}  // namespace test_helpers
