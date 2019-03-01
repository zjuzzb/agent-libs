#pragma once

#include <string>
#include <unordered_map>

class userdb {
public:
	const std::string& lookup(int64_t uid);

private:
	std::string getpwuid(int64_t uid);
	std::unordered_map<int64_t, std::string> m_uidmap;
};