//
// marathon_dispatcher.cpp
//

#include "marathon_dispatcher.h"
#include "mesos_event_data.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include <assert.h>
#include <stdexcept>
#include <algorithm>
#include <sstream>
#include <iostream>


marathon_dispatcher::marathon_dispatcher(mesos_state_t& state, const std::string& framework_id):
	m_state(state),
	m_framework_id(framework_id)
{
}

void marathon_dispatcher::enqueue(mesos_event_data&& event_data)
{
	m_messages.emplace_back(event_data.data());
	dispatch();
}

void marathon_dispatcher::log_error(const Json::Value& root, const std::string& comp)
{
	std::string unk_err = "Unknown.";
	std::ostringstream os;
	//TODO
	os << unk_err;
	g_logger.log(os.str(), sinsp_logger::SEV_ERROR);
}

void marathon_dispatcher::handle_status_update(const Json::Value& root)
{
	std::string slave_id = get_json_string(root, "slaveId");
	if(!slave_id.empty())
	{
		std::string task_status = get_json_string(root, "taskStatus");
		if(!task_status.empty())
		{
			std::string task_id = get_json_string(root, "taskId");
			if(!task_id.empty())
			{
				g_logger.log("Slave [" + slave_id + "], task " + get_json_string(root, "appId") + " (" + 
					task_id + ") changed status to " + task_status + 
					".\nVersion: " + get_json_string(root, "version") + 
					", Timestamp: " + get_json_string(root, "version"), sinsp_logger::SEV_INFO);

				if(task_status == "TASK_RUNNING")
				{
					std::string task_name;
					std::string::size_type pos = task_id.rfind('.');
					if(pos != std::string::npos && pos > 0)
					{
						task_name = task_id.substr(0, pos);
					}
					std::shared_ptr<mesos_task> t(new mesos_task(task_name, task_id));
					t->set_slave_id(slave_id);
					//add_labels(t, task);
					m_state.add_or_replace_task(m_state.get_framework(m_framework_id), t);
				}
				else if(task_status == "TASK_FINISHED" || // TERMINAL. The task finished successfully.
					task_status == "TASK_FAILED"       || // TERMINAL. The task failed to finish successfully.
					task_status == "TASK_KILLED"       || // TERMINAL. The task was killed by the executor.
					task_status == "TASK_LOST"         || // TERMINAL. The task failed but can be rescheduled.
					task_status == "TASK_ERROR")          // TERMINAL. The task description contains an error.
				{
					g_logger.log("Removing task [" + task_id + "]. Termination message: "+ get_json_string(root, "message"), sinsp_logger::SEV_INFO);
					try
					{
						m_state.remove_task(m_state.get_framework(m_framework_id), task_id);
					}
					catch(std::exception& ex)
					{
						g_logger.log(ex.what(), sinsp_logger::SEV_ERROR);
						return;
					}
					g_logger.log("Succesfully removed task [" + task_id + ']', sinsp_logger::SEV_INFO);
				}
				else
				{
					// Ignored:
					// TASK_STAGING; // Initial state. Framework status updates should not use.
					// TASK_STARTING;
					g_logger.log("Slave [" + slave_id + "], task " + get_json_string(root, "appId") + " (" + 
						task_id + ") ignored changed status to " + task_status, sinsp_logger::SEV_DEBUG);
				}
			}
		}
	}
}

void marathon_dispatcher::handle_deployment_success(const Json::Value& root)
{
	g_logger.log("MESOS_DEPLOYMENT_SUCCESS_EVENT", sinsp_logger::SEV_DEBUG);
}

void marathon_dispatcher::extract_data(const std::string& json, bool enqueue)
{
	Json::Value root;
	Json::Reader reader;
	if(reader.parse(json, root, false))
	{
		switch(mesos_event_data::get_event_type(root))
		{
			case mesos_event_data::MESOS_STATUS_UPDATE_EVENT:
				handle_status_update(root);
				break;
			case mesos_event_data::MESOS_DEPLOYMENT_SUCCESS_EVENT:
				handle_deployment_success(root);
				break;
			default:
			{
				std::string evt;
				Json::Value ev_type = root["eventType"];
				if(!ev_type.isNull() && ev_type.isString())
				{
					evt = ev_type.asString();
				}
				g_logger.log("marathon_dispatcher::extract_data: Unknown event " + evt, sinsp_logger::SEV_WARNING);
			}
		}
	}
}

void marathon_dispatcher::dispatch()
{
	for (list::iterator it = m_messages.begin(); it != m_messages.end();)
	{
		extract_data(*it, true);
		it = m_messages.erase(it);
	}
}

