#pragma once

#include "sinsp.h"

namespace Poco {
class RegularExpression;
}

/* size of the environment hash output, in bytes, must be <= 64 */
#define ENV_HASH_SIZE 32

class env_hash {
public:
	using hash_buf_t = std::array<char, ENV_HASH_SIZE>;
	using regex_list_t = std::list<Poco::RegularExpression>;

	void update(sinsp_threadinfo* tinfo, const regex_list_t& blacklist);
	const hash_buf_t& get_hash() const {
		return m_env_hash;
	}

	bool operator==(const env_hash& other) const {
		return m_env_hash == other.m_env_hash;
	}

private:
	hash_buf_t m_env_hash;
};

namespace std {
	template<> struct hash<env_hash> {
		std::size_t operator()(const env_hash& h) const {
			size_t hash;
			static_assert(ENV_HASH_SIZE >= sizeof(hash), "ENV_HASH_SIZE must be at least as long as a size_t");
			memcpy(&hash, h.get_hash().data(), sizeof(hash));
			return hash;
		}
	};
}