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

const std::string mesos::default_state_uri    = "http://localhost:5050";
const std::string mesos::default_state_api    = "/master/state";
const std::string mesos::default_marathon_uri = "http://localhost:8080";
const std::string mesos::default_groups_api   = "/v2/groups";
const std::string mesos::default_apps_api     = "/v2/apps?embed=apps.tasks";
const std::string mesos::default_watch_api    = "/v2/events";

mesos::mesos(const std::string& state_uri,
	const std::string& state_api,
	const std::string& marathon_uri,
	const std::string& groups_api,
	const std::string& apps_api,
	const std::string& watch_api): m_state_http(*this, state_uri + state_api),
		m_marathon_groups_http(marathon_uri.empty() || groups_api.empty()  ? 0 : new marathon_http(*this, marathon_uri + groups_api)),
		m_marathon_apps_http(marathon_uri.empty() || apps_api.empty()  ? 0 : new marathon_http(*this, marathon_uri + apps_api)),
		m_marathon_watch_http(marathon_uri.empty() || watch_api.empty() ? 0 : new marathon_http(*this, marathon_uri + watch_api, true)),
		m_dispatch(m_marathon_watch_http ? new marathon_dispatcher(m_state, m_marathon_watch_http->get_id()) : 0)
{
	refresh(!marathon_uri.empty());
}

mesos::~mesos()
{
	delete m_marathon_groups_http;
	delete m_marathon_apps_http;
	delete m_dispatch;
	delete m_marathon_watch_http;
}

void mesos::refresh(bool marathon)
{
	clear(marathon);

	m_state_http.get_all_data(&mesos::parse_state);

	if(marathon)
	{
		if(m_marathon_apps_http)
		{
			m_marathon_apps_http->get_all_data(&mesos::parse_apps);
		}

		if(m_marathon_groups_http)
		{
			m_marathon_groups_http->get_all_data(&mesos::parse_groups);
		}

		if(m_marathon_watch_http)
		{
			m_collector.add(m_marathon_watch_http);
		}
	}
}

void mesos::watch()
{
	if(m_marathon_watch_http)
	{
		if(!m_collector.subscription_count())
		{
			m_collector.add(m_marathon_watch_http);
		}
		m_collector.get_data();
	}
}

void mesos::determine_node_type(const Json::Value& root)
{
	Json::Value flags = root["flags"];
	if(!flags.isNull())
	{
		Json::Value port = flags["port"];
		if(!port.isNull())
		{
			if(port.asString() == "5050")
			{
				m_node_type = NODE_MASTER;
			}
			else if(port.asString() == "5051")
			{
				m_node_type = NODE_SLAVE;
			}
			else
			{
				throw sinsp_exception("Can not determine node type");
			}
		}
	}
}

void mesos::on_watch_data(mesos_event_data&& msg)
{
	m_dispatch->enqueue(std::move(msg));
}

void mesos::parse_state(const std::string& json)
{
	Json::Value root;
	Json::Reader reader;
	if(reader.parse(json, root, false))
	{
		//g_logger.log(root.toStyledString(), sinsp_logger::SEV_DEBUG);
		determine_node_type(root);
		handle_frameworks(root);
		handle_slaves(root);
	}
	else
	{
		throw sinsp_exception("Invalid JSON (parsing Mesos state failed).");
	}
}

void mesos::handle_frameworks(const Json::Value& root)
{
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

void mesos::handle_slaves(const Json::Value& root)
{
	Json::Value slaves = root["slaves"];
	if(!slaves.isNull())
	{
		for(const auto& slave : slaves)
		{
			add_slave(slave);
		}
	}
	else
	{
		g_logger.log("No frameworks found.", sinsp_logger::SEV_WARNING);
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

void mesos::add_slave(const Json::Value& slave)
{
	std::string name, uid;
	Json::Value sname = slave["hostname"];
	Json::Value sid = slave["id"];
	if(!sname.isNull())
	{
		name = sname.asString();
	}
	if(!sid.isNull())
	{
		uid = sid.asString();
	}
	std::ostringstream os;
	os << "Adding Mesos slave: [" << name << ',' << uid << ']';
	g_logger.log(os.str(), sinsp_logger::SEV_INFO);
	m_state.emplace_slave(mesos_slave(name, uid));
}

void mesos::add_tasks_impl(mesos_framework& framework, const Json::Value& tasks)
{
	if(!tasks.isNull())
	{
		for(const auto& task : tasks)
		{
			std::string name, uid, sid;
			Json::Value fname = task["name"];
			if(!fname.isNull()) { name = fname.asString(); }
			Json::Value fid = task["id"];
			if(!fid.isNull()) { uid = fid.asString(); }
			Json::Value fsid = task["slave_id"];
			if(!fsid.isNull()) { sid = fsid.asString(); }

			std::ostringstream os;
			os << "Adding Mesos task: [" << framework.get_name() << ':' << name << ',' << uid << ']';
			g_logger.log(os.str(), sinsp_logger::SEV_DEBUG);
			std::shared_ptr<mesos_task> t(new mesos_task(name, uid));
			t->set_slave_id(sid);
			add_labels(t, task);
			m_state.add_or_replace_task(framework, t);
		}
	}
	else
	{
		g_logger.log("tasks is null", sinsp_logger::SEV_DEBUG);
	}
}

void mesos::add_tasks(mesos_framework& framework, const Json::Value& f_val)
{
	if(is_master())
	{
		Json::Value tasks = f_val["tasks"];
		add_tasks_impl(framework, tasks);
	}
	else
	{
		Json::Value executors = f_val["executors"];
		if(!executors.isNull())
		{
			for(const auto& executor : executors)
			{
				Json::Value tasks = executor["tasks"];
				add_tasks_impl(framework, tasks);
			}
		}
	}
}

void mesos::add_labels(std::shared_ptr<mesos_task> task, const Json::Value& t_val)
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
			task->emplace_label(mesos_pair_t(key, val));
		}
	}
}

void mesos::handle_groups(const Json::Value& root, marathon_group::ptr_t to_group)
{
	Json::Value groups = root["groups"];
	if(!groups.isNull())
	{
		if(groups.size())
		{
			for(const auto& group : groups)
			{
				to_group = add_group(group, to_group);
				ASSERT(to_group);
				handle_groups(group, to_group);
			}
		}
	}
	else
	{
		g_logger.log("No groups found.", sinsp_logger::SEV_WARNING);
	}
}

void mesos::parse_groups(const std::string& json)
{
	Json::Value root;
	Json::Reader reader;
	if(reader.parse(json, root, false))
	{
		handle_groups(root, add_group(root, 0));
	}
	else
	{
		throw sinsp_exception("Invalid JSON (Marathon groups parsing failed).");
	}
}

marathon_group::ptr_t mesos::add_group(const Json::Value& group, marathon_group::ptr_t to_group)
{
	Json::Value group_id = group["id"];
	if(!group_id.isNull())
	{
		std::string id = group_id.asString();
		g_logger.log("Adding Marathon group [" + id + "] to group [" + (to_group ? to_group->get_id() : "/") + ']', sinsp_logger::SEV_DEBUG);
		marathon_group::ptr_t pg(new marathon_group(id));
		marathon_group::ptr_t p_group = m_state.add_or_replace_group(pg, to_group);
		Json::Value apps = group["apps"];
		if(!apps.isNull())
		{
			for(const auto& app : apps)
			{
				Json::Value app_id = app["id"];
				if(!app_id.isNull())
				{
					marathon_app::ptr_t p_app = m_state.get_app(app_id.asString());
					p_group->add_or_replace_app(p_app);
				}
			}
		}
		return p_group;
	}
	return 0;
}

void mesos::parse_apps(const std::string& json)
{
	Json::Value root;
	Json::Reader reader;
	if(reader.parse(json, root, false))
	{
		//g_logger.log(root.toStyledString(), sinsp_logger::SEV_DEBUG);
		Json::Value apps = root["apps"];
		if(!apps.isNull())
		{
			for(const auto& app : apps)
			{
				add_app(app);
			}
		}
		else
		{
			g_logger.log("No groups found.", sinsp_logger::SEV_WARNING);
		}
	}
	else
	{
		throw sinsp_exception("Invalid JSON (Marathon apps parsing failed).");
	}
}

void mesos::add_app(const Json::Value& app)
{
	Json::Value app_id = app["id"];
	if(!app_id.isNull())
	{
		std::string id = app_id.asString();
		g_logger.log("Adding Marathon app: " + id, sinsp_logger::SEV_DEBUG);
		marathon_app::ptr_t p_app(new marathon_app(id));
		m_state.add_or_replace_app(p_app);
		Json::Value tasks = app["tasks"];
		for(const auto& task : tasks)
		{
			Json::Value task_id = task["id"];
			if(!task_id.isNull())
			{
				g_logger.log("Adding Marathon task: " + task_id.asString(), sinsp_logger::SEV_DEBUG);
				mesos_framework::task_ptr_t pt = m_state.get_task(task_id.asString());
				if(pt)
				{
					pt->set_app_id(id);
					p_app->add_task(pt->get_uid());
				}
				else
				{
					throw sinsp_exception("Marathon task not found in mesos state");
				}
			}
		}
	}
}


