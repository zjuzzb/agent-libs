//
// mesos.cpp
//

#include "mesos.h"
#include "mesos_component.h"
#include "sinsp.h"
#include "sinsp_int.h"

const mesos_component::component_map mesos::m_components =
{
	{ mesos_component::MESOS_FRAMEWORK, "framework" },
	{ mesos_component::MESOS_TASK,      "task"      },
	{ mesos_component::MESOS_SLAVE,     "slave"     }
};


mesos::mesos(const std::string& uri, const std::string& api): m_http(*this, uri + api)
{
	std::ostringstream os;
	m_http.get_all_data(os);
	parse_json(os.str());
}

mesos::~mesos()
{
}

void mesos::parse_json(const std::string& json)
{
	Json::Value root;
	Json::Reader reader;
	if(reader.parse(json, root, false))
	{
		//g_logger.log(root.toStyledString(), sinsp_logger::SEV_DEBUG);
		Json::Value frameworks = root["frameworks"];
		if(!frameworks.isNull())
		{
			for(const auto& framework : frameworks)
			{
				add_framework(framework);
			}
		}
		else
		{
			g_logger.log("No frameworks found.", sinsp_logger::SEV_WARNING);
		}
	}
	else
	{
		throw sinsp_exception("Invalid JSON (parsing failed).");
	}
}

void mesos::add_framework(const Json::Value& framework)
{
	std::string name, uid;
	Json::Value fname = framework["name"];
	Json::Value fid = framework["id"];
	if(!fname.isNull())
	{
		name = fname.asString();
	}
	if(!fid.isNull())
	{
		uid = fid.asString();
	}
	std::ostringstream os;
	os << "Adding Mesos framework: [" << name << ',' << uid << ']';
	g_logger.log(os.str(), sinsp_logger::SEV_INFO);
	m_state.emplace_framework(mesos_framework(name, uid));
	add_tasks(m_state.get_frameworks().back(), framework);
}

void mesos::add_tasks(mesos_framework& framework, const Json::Value& f_val)
{
	Json::Value executors = f_val["executors"];
	if(!executors.isNull())
	{
		for(const auto& executor : executors)
		{
			Json::Value tasks = executor["tasks"];
			if(!tasks.isNull())
			{
				for(const auto& task : tasks)
				{
					std::string name, uid;
					Json::Value fname = task["name"];
					Json::Value fid = task["id"];
					if(!fname.isNull())
					{
						name = fname.asString();
					}
					if(!fid.isNull())
					{
						uid = fid.asString();
					}
					std::ostringstream os;
					os << "Adding Mesos task: [" << framework.get_name() << ':' << name << ',' << uid << ']';
					g_logger.log(os.str(), sinsp_logger::SEV_DEBUG);
					mesos_task t = mesos_task(name, uid);
					add_labels(t, task);
					m_state.add_or_replace_task(framework, std::move(t));
				}
			}
		}
	}
}

void mesos::add_labels(mesos_task& task, const Json::Value& t_val)
{
	Json::Value labels = t_val["labels"];
	if(!labels.isNull())
	{
		for(const auto& label : labels)
		{
			std::string key, val;
			Json::Value lkey = label["key"];
			Json::Value lval = label["value"];
			if(!lkey.isNull())
			{
				key = lkey.asString();
			}
			if(!lval.isNull())
			{
				val = lval.asString();
			}
			std::ostringstream os;
			os << "Adding Mesos task label: [" << key << ':' << val << ']';
			g_logger.log(os.str(), sinsp_logger::SEV_DEBUG);
			task.emplace_label(mesos_pair_t(key, val));
		}
	}
}
