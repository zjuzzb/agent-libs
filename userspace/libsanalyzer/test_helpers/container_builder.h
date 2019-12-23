#pragma once

#include "container_info.h"
#include <functional>

namespace test_helpers
{

/**
 * Easy way to create container_info in unit test. Setters are provided
 * for many fields and the class (should) create defaults for any mandatory
 * fields that the client does explicitly set. Each setter returns *this so
 * that the setters can be called in sequence.
 *
 * This is meant to be constructed by a test_helper that sets the commit
 * delegate before passing the container_builder back to the client.
 *
 * Usage: mock.build_container().id("12345").name("sysdig-agent").commit()
 */
class container_builder
{
public:

	using commit_delegate = std::function<void(const sinsp_container_info::ptr_t&,
						   sinsp_threadinfo&)>;
	/**
	 * ctor with a commit delegate where the generated events are
	 * sent to a consumer.
	 */
	container_builder(sinsp_threadinfo& tinfo,
			  const commit_delegate& delegate) :
	   m_commit(delegate),
	   m_container_info(new sinsp_container_info()),
	   m_tinfo(tinfo)
	{
		set_defaults();
	}

	/**
	 * Set the id
	 */
	container_builder& id(const std::string &value)
	{
		m_container_info->m_id = value;
		m_tinfo.m_container_id = value;
		return *this;
	}

	/**
	 * Set the name
	 */
	container_builder& name(const std::string& value)
	{
		m_container_info->m_name = value;
		return *this;
	}

	/**
	 * Complete the container_info and pass a const version to both the consumer
	 * and back to the client.
	 */
	sinsp_container_info::ptr_t commit()
	{
		fill_empty_fields();
		m_commit(m_container_info, m_tinfo);
		return m_container_info;
	}
private:

	void set_defaults()
	{
		m_container_info->m_type = CT_DOCKER;
	}

	void fill_empty_fields()
	{
		if(m_container_info->m_name.empty())
		{
			static char letter = 'a';
			std::string container_name = std::string("container_") + (letter++);
			name(container_name);

		}
		if(m_container_info->m_id.empty())
		{
			std::string container_id = m_container_info->m_name + "_id";
			id(container_id);
		}
	}

	commit_delegate m_commit;
	std::shared_ptr<sinsp_container_info> m_container_info;
	sinsp_threadinfo& m_tinfo;

};

}
