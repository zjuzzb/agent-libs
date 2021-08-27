#include "sinsp_evt_clone.h"

#include "capture_job_handler.h"

#include <utility>

namespace
{
COMMON_LOGGER();
}

static type_config<bool> wait_for_container_info(true,
                                                 "Wait for delayed container info",
                                                 "falco_alert_wait_container_info",
                                                 "enabled");

static type_config<int> wait_for_info_max_delay(667,
                                                "Max delay time ms",
                                                "falco_alert_wait_container_info",
                                                "max_delay_ms");

static type_config<int> wait_for_info_max_que(1024,
                                              "Max delayed que len",
                                              "falco_alert_wait_container_info",
                                              "max_delayed_que");


// sinsp event clone to keep scap data till container info arrives
sinsp_evt_clone::sinsp_evt_clone(std::string container_id, match_results_t& match_results)
    : sinsp_evt(),
      m_id(next_id()),
      m_created_at(infra_clock::now()),
      m_container_id(std::move(container_id)),
      m_match_results(match_results)
{
}

// clone factory
sinsp_evt_clone* sinsp_evt_clone::create(const sinsp_evt& evt,
										 const std::string& container_id,
                                         match_results_t& match_results)
{

	std::unique_ptr<sinsp_evt_clone> clone(new sinsp_evt_clone(container_id, match_results));
	if (!sinsp_evt::evtcpy(*clone, evt) )
	{
		LOG_WARNING("unable to clone event");
		return nullptr;
	}
	return clone.release();
}

/*
 * sinsp_evt_clone_registry class
 * to keep books on cloned events
 */
sinsp_evt_clone_registry::sinsp_evt_clone_registry(const callback_t& clbk,
                                                   const expired_callback_t& exp_clbk,
                                                   sinsp& inspector)
    : m_clbk(clbk),
      m_expired_callback(exp_clbk),
      m_inspector(inspector)
{
}

// create and put cloned event into maps
bool sinsp_evt_clone_registry::register_event(
    const std::string& container_id,
    const sinsp_evt& evt,
    match_results_t& match_results)
{
	auto event = sinsp_evt_clone::create(evt, container_id, match_results);
	if (event == nullptr)
	{
		return false;
	}

	m_evt_by_container.emplace(container_id, event->m_id);
	m_evt_by_timestamp.emplace(event->m_id, std::unique_ptr<sinsp_evt_clone>(event));

	return true;
}

// run events that match the container id
void sinsp_evt_clone_registry::on_new_container(const sinsp_container_info& ci)
{
	on_new_container(ci.m_id, ci.m_type);
}

void sinsp_evt_clone_registry::on_new_container(const std::string& ci, sinsp_container_type cty)
{
	LOG_DEBUG(
		"on_new_container for con_id=%s, interface_type=%d, ts_map_size=%lu, cont_map_size=%lu",
		ci.c_str(),
		cty,
		m_evt_by_timestamp.size(),
		m_evt_by_container.size());

	bool first_logged = false;
	for (auto cid_iter = m_evt_by_container.lower_bound(std::make_pair(ci, 0));
	     cid_iter != m_evt_by_container.end() && cid_iter->first == ci;)
	{
		if (!first_logged)
		{
			LOG_DEBUG("processing delayed events for con_id=%s, interface_type=%d",
			          ci.c_str(),
			          cty);
			first_logged = true;
		}

		auto evt_clone_it = m_evt_by_timestamp.find(cid_iter->second);
		if (evt_clone_it == m_evt_by_timestamp.end())
		{
			LOG_WARNING(
			    "clone event registry data inconsistency detected; container_id=%s clone_id=%lu",
			    ci.c_str(),
			    cid_iter->second);
		}
		else
		{
			m_clbk(evt_clone_it->second.get());
			m_evt_by_timestamp.erase(evt_clone_it);
		}
		cid_iter = m_evt_by_container.erase(cid_iter);
	}
}

// default exp check interval
const chrono::duration<int64_t, milli> exp_check_interval = std::chrono::milliseconds(3);

// run expired events
void sinsp_evt_clone_registry::check_expired()
{
	auto now = infra_clock::now();

	if (std::chrono::duration_cast<std::chrono::milliseconds>(now - m_last_exp_check) <
	    exp_check_interval)
	{
		return;
	}

	m_last_exp_check = now;
	auto expiration = now - std::chrono::milliseconds(wait_for_info_max_delay.get_value());

	for (auto id_iter = m_evt_by_timestamp.begin();
	     id_iter != m_evt_by_timestamp.end() && id_iter->second->m_created_at < expiration;)
	{
		LOG_DEBUG("processing expired event; age=%lu ",
		          std::chrono::duration_cast<std::chrono::milliseconds>(
		              now - id_iter->second->m_created_at)
		              .count());

		m_expired_callback(id_iter->second.get(),
		                   id_iter->second->m_match_results,
		                   id_iter->second->get_thread_info(),
		                   &id_iter->second->m_container_id);

		m_evt_by_container.erase(
		    std::make_pair(id_iter->second->m_container_id, id_iter->second->m_id));
		id_iter = m_evt_by_timestamp.erase(id_iter);
	}
}

// check if can register event
bool sinsp_evt_clone_registry::can_register(const gen_event* evt, const std::string* container_id)
{
	if (container_id == nullptr || container_id->empty())
	{
		return false;
	}

	if (evt->get_source() != ESRC_SINSP)
	{
		return false;
	}

	if (m_evt_by_timestamp.size() > wait_for_info_max_que.get_value())
	{
		LOG_WARNING("Delayed events queue size is greater than limit=%d",
		            wait_for_info_max_que.get_value());
		return false;
	}

	if (!check_integrity())
	{
		LOG_WARNING("Delayed events storage is invalid");
		return false;
	}

	return wait_for_container_info.get_value() &&
	       dynamic_cast<const sinsp_evt_clone*>(evt) == nullptr;
}

// verify integrity
bool sinsp_evt_clone_registry::check_integrity()
{
	return m_evt_by_container.size() == m_evt_by_timestamp.size();
}
