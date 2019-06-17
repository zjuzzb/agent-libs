#include <scap.h>
#include <sys/stat.h>
#include "container_config.h"

namespace
{
bool is_socket(const std::string &path)
{
	std::string actual_path = scap_get_host_root() + path;
	struct stat s = {};
	if (stat(actual_path.c_str(), &s) == -1)
	{
		return false;
	}

	return (s.st_mode & S_IFMT) == S_IFSOCK;
}
}


type_config<int64_t> c_cri_timeout_ms(
	1000,
	"Maximum time to wait for CRI runtime response",
	"cri", "timeout_ms");

type_config<bool> c_cri_async(
	false,
	"Use asynchronous lookups of CRI metadata",
	"cri", "async");

type_config<bool> c_cri_async_limits(
	false,
	"Use asynchronous lookups of CRI resource limits (non-containerd)",
	"cri", "async_limits");

type_config<bool> c_cri_extra_queries(
	false,
	"Enable additional CRI queries for extra metadata",
	"cri", "extra_queries");

type_config<std::vector<std::string>> c_cri_known_socket_paths(
	{},
	"Known paths for the CRI socket",
	"cri", "known_socket_paths");

type_config<std::string>::ptr c_cri_socket_path = type_config_builder<std::string>(
	"",
	"Path to the CRI socket",
	"cri", "socket_path")
	.post_init([](type_config<std::string>& config) {
		if(config.get().empty())
		{
			for(const auto& path : c_cri_known_socket_paths.configured())
			{
				if(is_socket(path))
				{
					config.set(path);
					return;
				}
			}
		}
		else if(!is_socket(config.get()))
		{
			config.set("");
		}
	}).get();
