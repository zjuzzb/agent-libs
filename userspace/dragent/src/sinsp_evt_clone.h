
#pragma once


#include <container.h>
#include <event.h>
#include <infrastructure_state.h>
#include "security_rule.h"

#include <memory>

/**
 * sinsp_evt_clone class to provide a wrapper for sinsp_evt
 * It allows to copy & store original sinsp_evt until either:
 *  1. missing info arrives
 *  2. wait timeout expired
 */
class sinsp_evt_clone : public sinsp_evt
{
	using t_info_ptr_t = std::shared_ptr<sinsp_threadinfo>;
	using match_results_t = std::shared_ptr<std::list<security_rules::match_result>>;

public:
	/**
	 * event creation factory
	 */
	static sinsp_evt_clone* create(const sinsp_evt& evt,
	                               const std::string& container_id,
	                               match_results_t& match_results);

	/**
	 * base class overrides
	 * @return
	 */
	uint16_t get_source() const override { return ESRC_SINSP; }

	/**
	 * dtor
	 */
	~sinsp_evt_clone() override = default;

private:

	static uint64_t next_id()
	{
		// no need for atomic until whole thing is thread safe
		static uint64_t id(0);
		return ++id;
	}

	explicit sinsp_evt_clone(std::string container_id, match_results_t& match_results);

	friend class sinsp_evt_clone_registry;

	// fields used by the registry to index  the events
	const uint64_t m_id;
	const infra_time_point_t m_created_at{};
	const std::string m_container_id;

	// results calculated on the first pass
	match_results_t m_match_results;
};

/**
 * registry for the incomplete events
 */
class sinsp_evt_clone_registry final
{
	using match_results_t = std::shared_ptr<std::list<security_rules::match_result>>;
	using callback_t = std::function<void(gen_event* evt)>;

	using expired_callback_t = std::function<void(const gen_event* evt,
	                                              const match_results_t& results,
	                                              const sinsp_threadinfo* tinfo,
	                                              const std::string* container_id_ptr)>;

public:

	/**
	 * ctor
	 */
	sinsp_evt_clone_registry(const callback_t& clbk,
	                         const expired_callback_t& expired_callback,
	                         sinsp& inspector);

	/**
	 * check if can save evt to the registry
	 */
	bool can_register(const gen_event* evt, const std::string* container_id);

	/**
	 * Do the registration
	 */
	bool register_event(const std::string& container_id, const sinsp_evt& evt,
						match_results_t& match_results);

	/**
	 * new container info callback
	 */
	void on_new_container(const sinsp_container_info&);

	/*
	 * verify events expiration status
	 */
	void check_expired();

private:
	callback_t m_clbk;
	expired_callback_t m_expired_callback;
	sinsp& m_inspector;
	infra_time_point_t m_last_exp_check;

	void on_new_container(const std::string&, sinsp_container_type);

	bool check_integrity();

	std::set<std::pair<std::string, uint64_t>> m_evt_by_container;
	std::map<uint64_t, std::unique_ptr<sinsp_evt_clone>> m_evt_by_timestamp;
};
