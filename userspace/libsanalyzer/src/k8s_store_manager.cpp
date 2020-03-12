#include "k8s_store_manager.h"

k8s_store_manager::k8s_store_manager()
{
}

void k8s_store_manager::handle_add(const state_key_t& key, state_t& state)
{
	for(auto& store : m_stores)
	{
		store->handle_add(key, state);
	}
}

void k8s_store_manager::handle_update(const state_key_t& key, state_t& state)
{
	for(auto& store : m_stores)
	{
		store->handle_update(key, state);
	}
}

void k8s_store_manager::handle_delete(const state_key_t& key, state_t& state)
{
	for(auto& store : m_stores)
	{
		store->handle_delete(key, state);
	}
}

void k8s_store_manager::clear()
{
	for(auto& store : m_stores)
	{
		store->clear();
	}
}

uint64_t k8s_store_manager::size()
{
	uint64_t ret(0);
	for(const auto& store : m_stores)
	{
		ret += store->size();
	}

	return ret;
}

void k8s_store_manager::print_store_status() const
{
	for(auto& store : m_stores)
	{
		store->print_store_status();
	}
}
