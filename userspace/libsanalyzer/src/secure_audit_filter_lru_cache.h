#pragma once

#include "Poco/LRUCache.h"
#include "Poco/SharedPtr.h"

namespace audit_cache
{
class AuditFilterLRUCache
{
private:
	Poco::LRUCache<std::string, int> m_cache;

public:
	AuditFilterLRUCache(const int cacheSize) : m_cache(cacheSize) {}

	int Get(std::string key)
	{
		int* value = m_cache.get(key);
		return value == nullptr ? 0 : *value;
	}

	bool Has(std::string key) { return m_cache.has(key); }

	void Put(std::string key, int value) { m_cache.add(key, value); }

	int Size() { return m_cache.size(); }
};
}  // namespace audit_cache