#include "env_hash.h"
#include "blake2/blake2.h"

#include <Poco/RegularExpression.h>

void env_hash::update(sinsp_threadinfo* tinfo, const env_hash::regex_list_t & blacklist)
{
	blake2b_state S[1];
	blake2b_init(S, m_env_hash.size());
	for (const auto& var: tinfo->get_env()) {
		bool blacklisted = false;
		for (const auto& regex: blacklist) {
			if (regex.match(var)) {
				blacklisted = true;
				break;
			}
		}
		if (!blacklisted) {
			blake2b_update(S, var.c_str(), var.size() + 1);
		}
	}
	blake2b_final(S, m_env_hash.data(), m_env_hash.size());
}
