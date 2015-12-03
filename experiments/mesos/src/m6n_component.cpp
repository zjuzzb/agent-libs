//
// m6n_component.cpp
//

#include "m6n_component.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include <sstream>
#include <iostream>

//
// component
//

const m6n_component::component_map m6n_component::list =
{
	{ m6n_component::M6N_GROUP, "group" },
	{ m6n_component::M6N_APP,   "app"   }
};

m6n_component::m6n_component(type t, const std::string& id) : 
	m_type(t),
	m_id(id)
{
	if(m_id.empty())
	{
		throw sinsp_exception("component name cannot be empty");
	}
}

m6n_component::m6n_component(const m6n_component& other): m_type(other.m_type),
	m_id(other.m_id)
{
}

m6n_component::m6n_component(m6n_component&& other):  m_type(other.m_type),
	m_id(std::move(other.m_id))
{
}

m6n_component& m6n_component::operator=(const m6n_component& other)
{
	m_type = other.m_type;
	m_id = other.m_id;
	return *this;
}

m6n_component& m6n_component::operator=(const m6n_component&& other)
{
	m_type = other.m_type;
	m_id = std::move(other.m_id);
	return *this;
}

std::string m6n_component::get_name(type t)
{
	component_map::const_iterator it = list.find(t);
	if(it != list.end())
	{
		return it->second;
	}

	std::ostringstream os;
	os << "Unknown component type " << static_cast<int>(t);
	throw sinsp_exception(os.str().c_str());
}

m6n_component::type m6n_component::get_type(const std::string& name)
{
	if(name == "group")
	{
		return M6N_GROUP;
	}
	else if(name == "app")
	{
		return M6N_APP;
	}

	std::ostringstream os;
	os << "Unknown component name " << name;
	throw sinsp_exception(os.str().c_str());
}

//
// app
//

m6n_app::m6n_app(const std::string& id) :
	m6n_component(m6n_component::M6N_APP, id)
{
}

m6n_app::~m6n_app()
{
}

void m6n_app::add_or_replace_task(mesos_task::ptr_t ptask)
{
	for(auto& task : m_tasks)
	{
		if(task->get_uid() == ptask->get_uid())
		{
			task = ptask;
			return;
		}
	}
	m_tasks.push_back(ptask);
}

//
// group
//

m6n_group::m6n_group(const std::string& id) :
	m6n_component(m6n_component::M6N_GROUP, id)
{
}

m6n_group::m6n_group(const m6n_group& other): m6n_component(other)
{
}

m6n_group::m6n_group(m6n_group&& other): m6n_component(std::move(other))
{
}

m6n_group& m6n_group::operator=(const m6n_group& other)
{
	m6n_component::operator =(other);
	return *this;
}

m6n_group& m6n_group::operator=(const m6n_group&& other)
{
	m6n_component::operator =(std::move(other));
	return *this;
}
