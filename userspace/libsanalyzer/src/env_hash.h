#pragma once

#include "sinsp.h"

namespace Poco {
class RegularExpression;
}

/**
 * Size of the environment hash output, in bytes.
 * env_hash.cpp uses two different hash implementations:
 * - Blake2b -- supports hash sizes up to 64
 * - SHA256 -- suppores hash size exactly 32
 * So, ENV_HASH_SIZE must be 32, to support both implementations.
 */
#define ENV_HASH_SIZE 32

class env_hash {
public:
	env_hash();

	using hash_buf_t = std::array<char, ENV_HASH_SIZE>;
	using regex_list_t = std::list<Poco::RegularExpression>;

	bool is_valid();
	void update(sinsp_threadinfo* tinfo, const regex_list_t& blacklist);
	const hash_buf_t& get_hash() const {
		return m_env_hash;
	}

	bool operator==(const env_hash& other) const {
		return m_env_hash == other.m_env_hash;
	}

private:
	hash_buf_t m_env_hash;
	bool m_env_hash_is_valid;
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

struct env_hash_config {
	uint32_t m_envs_per_flush;
	size_t m_max_env_size = 8192;
	std::unique_ptr<env_hash::regex_list_t> m_env_blacklist;
	uint64_t m_env_hash_ttl = 86400ULL * ONE_SECOND_IN_NS;
	bool m_send_metrics;
	bool m_send_audit_tap;
	bool m_track_environment;
};
