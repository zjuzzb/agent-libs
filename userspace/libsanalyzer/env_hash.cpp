#include "env_hash.h"
#include "blake2/blake2.h"

void env_hash::update(sinsp_threadinfo* tinfo)
{
	blake2b_state S[1];
	blake2b_init(S, m_env_hash.size());
	for (const auto& var: tinfo->get_env()) {
		blake2b_update(S, var.c_str(), var.size() + 1);
	}
	blake2b_final(S, m_env_hash.data(), m_env_hash.size());
}
