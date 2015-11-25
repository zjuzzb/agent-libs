//
// mesos_component.cpp
//

#include "mesos_component.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include <sstream>
#include <iostream>

//
// component
//

const mesos_component::component_map mesos_component::list =
{
	{ mesos_component::MESOS_FRAMEWORK, "framework" },
	{ mesos_component::MESOS_TASK,      "task"      },
	{ mesos_component::MESOS_SLAVE,     "slave"     }
};

mesos_component::mesos_component(type t, const std::string& name, const std::string& uid) : 
	m_type(t),
	m_name(name), m_uid(uid)
{
	if(m_name.empty())
	{
		throw sinsp_exception("component name cannot be empty");
	}

	if(m_uid.empty())
	{
		throw sinsp_exception("component uid cannot be empty");
	}
}

mesos_component::mesos_component(const mesos_component& other): m_name(other.m_name),
	m_uid(other.m_uid)
{
}

mesos_component::mesos_component(mesos_component&& other): m_name(std::move(other.m_name)),
	m_uid(std::move(other.m_uid))
{
}

mesos_component& mesos_component::operator=(const mesos_component& other)
{
	m_name = other.m_name;
	m_uid = other.m_uid;
	return *this;
}

mesos_component& mesos_component::operator=(const mesos_component&& other)
{
	m_name = std::move(other.m_name);
	m_uid = std::move(other.m_uid);
	return *this;
}

/*
mesos_pair_list mesos_component::extract_object(const Json::Value& object, const std::string& name)
{
	mesos_pair_list entry_list;

	if(!object.isNull())
	{
		Json::Value entries = object[name];
		if(!entries.isNull())
		{
			Json::Value::Members members = entries.getMemberNames();
			for (auto& member : members)
			{
				Json::Value val = entries[member];
				if(!val.isNull())
				{
					entry_list.emplace_back(mesos_pair_t(member, val.asString()));
				}
			}
		}
	}
	return entry_list;
}
*/

std::string mesos_component::get_name(type t)
{
	component_map::const_iterator it = list.find(t);
	if(it != list.end())
	{
	}

	std::ostringstream os;
	os << "Unknown component type " << static_cast<int>(t);
	throw sinsp_exception(os.str().c_str());
}

mesos_component::type mesos_component::get_type(const std::string& name)
{
	if(name == "framework")
	{
		return MESOS_FRAMEWORK;
	}
	else if(name == "task")
	{
		return MESOS_TASK;
	}
	else if(name == "slave")
	{
		return MESOS_SLAVE;
	}

	std::ostringstream os;
	os << "Unknown component name " << name;
	throw sinsp_exception(os.str().c_str());
}

mesos_pair_t* mesos_component::get_label(const mesos_pair_t& label)
{
	for (auto& lbl : m_labels)
	{
		if((lbl.first == label.first) && (lbl.second == label.second))
		{
			return &lbl;
		}
	}
	return 0;
}

void mesos_component::add_labels(mesos_pair_list&& labels)
{
	for (auto& label : labels)
	{
		if(!get_label(label))
		{
			emplace_label(std::move(label));
		}
	}
}


//
// framework
//

mesos_framework::mesos_framework(const std::string& name, const std::string& uid) :
	mesos_component(mesos_component::MESOS_FRAMEWORK, name, uid)
{
}

mesos_framework::~mesos_framework()
{
}

void mesos_framework::add_or_replace_task(const mesos_task& task)
{
	m_tasks.insert(task_map::value_type(task.get_uid(), task));
}

void mesos_framework::remove_task(const std::string& uid)
{
	task_map::iterator it = m_tasks.find(uid);
	if(it != m_tasks.end())
	{
		m_tasks.erase(it);
		return;
	}
	throw sinsp_exception("Removal attempted for non-existing task: " + uid);
}

const mesos_framework::task_map& mesos_framework::get_tasks() const
{
	return m_tasks;
}

//
// task
//

mesos_task::mesos_task(mesos_framework& framework, const std::string& name, const std::string& uid) :
	mesos_component(mesos_component::MESOS_TASK, name, uid),
	m_framework(&framework)
{
}

mesos_task::mesos_task(const mesos_task& other): mesos_component(other), m_framework(other.m_framework)
{
}

mesos_task::mesos_task(mesos_task&& other): mesos_component(std::move(other)), m_framework(other.m_framework)
{
}

mesos_task& mesos_task::operator=(const mesos_task& other)
{
	mesos_component::operator =(other);
	m_framework = other.m_framework;
	return *this;
}

mesos_task& mesos_task::operator=(const mesos_task&& other)
{
	mesos_component::operator =(std::move(other));
	m_framework = other.m_framework;
	return *this;
}

//
// slave
//

mesos_slave::mesos_slave(const std::string& name, const std::string& uid) :
	mesos_component(mesos_component::MESOS_SLAVE, name, uid)
{
}

