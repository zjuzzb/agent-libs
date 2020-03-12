#pragma once

#include <string>
#include <memory>
#include <map>
#include <vector>

#include "k8s_object_store.h"
#include "common_logger.h"

/*!
  This class contains all the caches that are used to
  create parent-child relationships. Its main purpose is to
  forward events to all the caches
 */
class k8s_store_manager
{
public:
	k8s_store_manager();

	k8s_store_manager(const k8s_store_manager&) = delete;
	k8s_store_manager& operator=(const k8s_store_manager&) = delete;

	k8s_store_manager(k8s_store_manager&& other)
		: m_stores(std::move(other.m_stores))
	{
	}

	using state_key_t = std::pair<std::string, std::string>;
	using state_t = std::map<std::pair<std::string, std::string>, std::unique_ptr<draiosproto::container_group>>;

	/*!
	  Handle an add event from cointerface.
	  \param key The cointerface container_group id
	  \param state A reference to cointerface infrastructure state
	 */
	void handle_add(const state_key_t& key, state_t& state);

	/*!
	  Handle an update event from cointerface.
	  \param key The cointerface container_group id
	  \param state A reference to cointerface infrastructure state
	 */
	void handle_update(const state_key_t& key, state_t& state);

	/*!
	  Handle a delete event from cointerface.
	  \param key The cointerface container_group id
	  \param state A reference to cointerface infrastructure state
	 */
	void handle_delete(const state_key_t& key, state_t& state);

	/*!
	  Request all the caches to clear their internal structures
	 */
	void clear();

	/*!
	  Collect the size of all the caches
	  \return The overall size of all the caches
	 */
	uint64_t size();

	/*!
	  Request all the caches to log some useful info about their internal caches
	 */
	void print_store_status() const;

private:
	template<typename... Args> friend class k8s_store_manager_builder;
	std::vector<std::unique_ptr<k8s_object_store>> m_stores;

	bool m_enabled;

};

/*!
  This class is designed to build the store manager.
  Template parameters must be the cache classes derived
  from k8s_object_store.
 */
template<typename... Args>
class k8s_store_manager_builder;

template<typename C>
class k8s_store_manager_builder<C>
{
public:
	/*!
	  The builder ctor
	  \param enable If true, the builder will create a manager with all the requested caches.
                        Oterwise it will create a manager with any cache.
	 */
	k8s_store_manager_builder(bool enable)
	{
		if(enable)
		{
			m_k8s_manager.m_stores.push_back(std::unique_ptr<C>(new C));
		}
		else
		{
			g_logger.log("k8s store manager disabled", sinsp_logger::SEV_DEBUG);
		}
	}

	/*!
	  \return The created manager
	 */
	k8s_store_manager& build()
	{
		return m_k8s_manager;
	}

protected:
	k8s_store_manager m_k8s_manager;
};

template<typename First, typename... Others>
class k8s_store_manager_builder<First, Others...> : public k8s_store_manager_builder<Others...>
{
public:
	k8s_store_manager_builder(bool enable)
		: k8s_store_manager_builder<Others...>(enable)
	{
		if(enable)
		{
			k8s_store_manager_builder<Others...>::m_k8s_manager.m_stores.push_back(std::unique_ptr<First>(new First));
		}
		else
		{
			g_logger.log("k8s store manager disabled", sinsp_logger::SEV_DEBUG);
		}
	}
};

