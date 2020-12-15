
namespace thread_safe_container
{

template<class TKey, class TValue>
bool guarded_cache<TKey, TValue>::insert(const TKey &key, const TValue &value)
{
	guard_t guard(m_lock);

	auto inserted = m_data.insert(std::make_pair(key, value));

	return inserted.second;
}

template<class TKey, class TValue>
bool  guarded_cache<TKey, TValue>::emplace(const TKey& key, TValue&& value)
{
	guard_t guard(m_lock);

	auto inserted = m_data.emplace(TKey(key), value);

	return inserted.second;
}

template<class TKey, class TValue>
bool guarded_cache<TKey, TValue>::erase(const TKey& key)
{
	guard_t guard(m_lock);

	return m_data.erase(key) > 0;
}

template<class TKey, class TValue>
typename guarded_cache<TKey, TValue>::const_element_handle guarded_cache<TKey, TValue>::read_handle(const TKey& key) const
{
	guard_t lock(m_lock);

	auto iter = m_data.find(key);

	if(iter == m_data.end())
	{
		return const_element_handle(std::unique_lock<std::mutex>(), nullptr);
	}

	return const_element_handle(std::move(lock), &(iter->second));
}

template<class TKey, class TValue>
typename guarded_cache<TKey, TValue>::element_handle guarded_cache<TKey, TValue>::read_write_handle(const TKey& key)
{
	guard_t lock(m_lock);

	auto iter = m_data.find(key);

	if(iter == m_data.end())
	{
		return element_handle(std::unique_lock<std::mutex>(), nullptr);
	}

	return element_handle(std::move(lock), &(iter->second));
}

template<class TKey, class TValue>
void guarded_cache<TKey, TValue>::visit(const std::function<void(const element_pair&)>& visitor) const
{
	guard_t guard(m_lock);


	for(const auto& element : m_data)
	{
		visitor(element);
	}
}

template<class TKey, class TValue>
void guarded_cache<TKey, TValue>::visit(const std::function<void(element_pair&)>& visitor)
{
	guard_t guard(m_lock);


	for(auto& element : m_data)
	{
		visitor(element);
	}
}

}
