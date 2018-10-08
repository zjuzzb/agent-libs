#include "userdb.h"
#include <pwd.h>

const std::string& userdb::lookup(int64_t uid)
{
	auto entry_it = m_uidmap.find(uid);
	if (entry_it != m_uidmap.end()) {
		return entry_it->second;
	}

	return (m_uidmap[uid] = getpwuid(uid));
}

std::string userdb::getpwuid(int64_t uid)
{
	struct passwd* pw = ::getpwuid((uid_t)uid);
	if (pw) {
		return pw->pw_name;
	} else {
		return "uid" + std::to_string(uid);
	}
}
