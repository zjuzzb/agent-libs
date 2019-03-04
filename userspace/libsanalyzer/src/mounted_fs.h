#pragma once

#include "posix_queue.h"
#include "mount_points_limits.h"

#ifdef EXPOSE_INTERNALS_MOUNTED_FS_H
#define MOUNTED_FS_H_VISIBILITY_PRIVATE public:
#else
#define MOUNTED_FS_H_VISIBILITY_PRIVATE private:
#endif

#include <istream>

namespace draiosproto {
class mounted_fs;
}

namespace sdc_internal {
class mounted_fs_request;
class mounted_fs_response;
}

class mounted_fs
{
public:
	mounted_fs():
		size_bytes(0),
		used_bytes(0),
		available_bytes(0),
		total_inodes(0),
		used_inodes(0)
	{
	}
	explicit mounted_fs(const draiosproto::mounted_fs& proto);
	mounted_fs(mounted_fs&&) = default;
	mounted_fs& operator=(mounted_fs&&) = default;

	void to_protobuf(draiosproto::mounted_fs* proto) const;

MOUNTED_FS_H_VISIBILITY_PRIVATE
	string device;
	string mount_dir;
	string type;
	uint64_t size_bytes;
	uint64_t used_bytes;
	uint64_t available_bytes;
	uint64_t total_inodes;
	uint64_t used_inodes;

	friend class sinsp_procfs_parser;
	friend class mounted_fs_reader;
};

struct mounted_fs_list
{
	std::unordered_map<std::string, std::vector<mounted_fs>> m_mounted_fs;
	std::unordered_map<dev_t, std::string> m_device_map;

	mounted_fs_list(decltype(m_mounted_fs)&& mounted_fs, decltype(m_device_map)&& device_map) :
		m_mounted_fs(std::move(mounted_fs)),
		m_device_map(std::move(device_map)) {}
};

class mounted_fs_proxy
{
public:
	explicit mounted_fs_proxy();
	mounted_fs_list receive_mounted_fs_list();
	bool send_container_list(const vector<sinsp_threadinfo*>& containers);
private:
	posix_queue m_input;
	posix_queue m_output;
};

class mounted_fs_reader
{
public:
	mounted_fs_reader(bool remotefs, const mount_points_filter_vec& mount_points, unsigned mounts_limit_size);
	int run();
	vector<mounted_fs> get_mounted_fs_list(const string& mtab="/etc/mtab");
	const mount_points_limits::sptr_t& get_limits() const {
		return m_mount_points;
	}

MOUNTED_FS_H_VISIBILITY_PRIVATE
#ifndef CYGWING_AGENT
	int handle_mounted_fs_request(const char* root_dir, int home_fd, const sdc_internal::mounted_fs_request& request,
		sdc_internal::mounted_fs_response& response);
#endif

#ifndef CYGWING_AGENT
	std::unordered_map<uint32_t, std::string> read_mountinfo(std::istream& mountinfo);
#endif

	static const uint16_t ERROR_EXIT = 1;
	static const uint16_t DONT_RESTART_EXIT = 17;
	static bool change_ns(int destpid);
	static int open_ns_fd(int pid);

	mount_points_limits::sptr_t m_mount_points;
	bool m_remotefs;
};
