#pragma once

#include <unordered_map>
#include "mutex.h"

namespace thread_safe_container
{

/**
 * An unordered map that protects access to itself and provides guarded
 * handles to read and write data.
 */
template<class TKey, class TValue>
class guarded_cache
{
public:
	guarded_cache() = default;

	/**
	 * Add an object to the map
	 * @return whether an item was inserted
	 */
	bool insert(const TKey& key, const TValue& value);

	/**
	 * Add an rvalue object to the map
	 */
	bool emplace(const TKey& key, TValue&& value);

	/**
	 * Erase an object from the map
	 * @return whether an item was erased
	 */
	bool erase(const TKey& key);

	using element_pair = std::pair<const TKey, TValue>;
	using const_element_handle = libsinsp::ConstMutexGuard<TValue>;
	using element_handle = libsinsp::MutexGuard<TValue>;

	/**
	 * Retrieve read-only access to an element of the map. the map will be
	 * locked while the handle exists.
	 */
	const_element_handle read_handle(const TKey& key) const;

	/**
	 * Retrieve read and write access to an element of the map. the map
	 * will be locked while the handle exists.
	 */
	element_handle read_write_handle(const TKey& key);

	/**
	 * Call the visitor on every const element of the map.
	 */
	void visit(const std::function<void(const element_pair&)>& visitor) const;

	/**
	 * Call the visitor on every element of the map.
	 */
	void visit(const std::function<void(element_pair&)>& visitor);

	guarded_cache(guarded_cache& rhs) = delete;
	guarded_cache& operator=(guarded_cache& rhs) = delete;

private:

	using guard_t = std::unique_lock<std::mutex>;
	using map_t = std::unordered_map<TKey, TValue>;

	mutable std::mutex m_lock;
	map_t m_data;
};

}