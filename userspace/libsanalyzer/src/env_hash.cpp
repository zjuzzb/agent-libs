#include "env_hash.h"

//
// env_hash supports use of two different hash algorithms:
// - BLAKE2 -- preferred for performance, but not available on all platforms
// - SHA256 -- available on all platforms
//
#ifdef __x86_64__
#define USE_HASH_ALGO_BLAKE2
#endif

#ifdef USE_HASH_ALGO_BLAKE2
#include "blake2/blake2.h"
#else
#include "openssl/sha.h"
#endif


#include <Poco/RegularExpression.h>

env_hash::env_hash()
	: m_env_hash_is_valid(false)
{
}

bool env_hash::is_valid()
{
	return m_env_hash_is_valid;
}

void env_hash::update(sinsp_threadinfo* tinfo, const env_hash::regex_list_t & blacklist)
{
#ifdef USE_HASH_ALGO_BLAKE2
	blake2b_state S[1];
	blake2b_init(S, m_env_hash.size());
#else
	ASSERT(ENV_HASH_SIZE == SHA256_DIGEST_LENGTH);
	SHA256_CTX S[1];
	SHA256_Init(S);
#endif
	for (const auto& var: tinfo->get_env()) {
		bool blacklisted = false;
		if(var.empty() || var[0] == '=') {
			continue;
		}
		for (const auto& regex: blacklist) {
			if (regex.match(var)) {
				blacklisted = true;
				break;
			}
		}
		if (!blacklisted) {
#ifdef USE_HASH_ALGO_BLAKE2
			blake2b_update(S, var.c_str(), var.size() + 1);
#else
			SHA256_Update(S, var.c_str(), var.size() + 1);
#endif
		}
	}
#ifdef USE_HASH_ALGO_BLAKE2
	blake2b_final(S, m_env_hash.data(), m_env_hash.size());
#else
	SHA256_Final((unsigned char *)m_env_hash.data(), S);
#endif

	m_env_hash_is_valid = true;
}
