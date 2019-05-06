#include "mounted_fs.h"
#include "sdc_internal.pb.h"
#include "setns.h"
#include "subprocess.h"

#include <unordered_set>
#include <mntent.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

mounted_fs::mounted_fs(const draiosproto::mounted_fs& proto):
	device(proto.device()),
	mount_dir(proto.mount_dir()),
	type(proto.type()),
	size_bytes(proto.size_bytes()),
	used_bytes(proto.used_bytes()),
	available_bytes(proto.available_bytes()),
	total_inodes(proto.total_inodes()),
	used_inodes(proto.used_inodes())
{

}

void mounted_fs::to_protobuf(draiosproto::mounted_fs *fs) const
{
	fs->set_device(device);
	fs->set_mount_dir(mount_dir);
	fs->set_type(type);
	fs->set_size_bytes(size_bytes);
	fs->set_used_bytes(used_bytes);
	fs->set_available_bytes(available_bytes);
	fs->set_total_inodes(total_inodes);
	fs->set_used_inodes(used_inodes);
}

mounted_fs_proxy::mounted_fs_proxy():
	m_input("/sdc_mounted_fs_reader_out", posix_queue::direction_t::RECEIVE),
	m_output("/sdc_mounted_fs_reader_in", posix_queue::direction_t::SEND)
{

}

mounted_fs_list mounted_fs_proxy::receive_mounted_fs_list()
{
#ifndef CYGWING_AGENT
	unordered_map<string, vector<mounted_fs>> fs_map;
	unordered_map<dev_t, string> device_map;
	auto last_msg = m_input.receive();
	decltype(last_msg) msg;
	while(!last_msg.empty())
	{
		msg = move(last_msg);
		last_msg = m_input.receive();
	}
	if(!msg.empty())
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "Received from mounted_fs_reader: %lu bytes", msg.size());
		sdc_internal::mounted_fs_response response_proto;
		if(response_proto.ParseFromString(msg))
		{
			fs_map.clear();
			for(const auto& c : response_proto.containers())
			{
				vector<mounted_fs> fslist;
				for( const auto& m : c.mounts())
				{
					fslist.emplace_back(m);
				}
				fs_map.emplace(c.container_id(), move(fslist));
			}
			for(const auto& d : response_proto.devices())
			{
				device_map.emplace(d.number(), d.name());
			}
		}
	}
	return mounted_fs_list(std::move(fs_map), std::move(device_map));
#else
	ASSERT(false);
	throw sinsp_exception("mounted_fs_proxy::receive_mounted_fs_list not implemented on Windows");
#endif
}

bool mounted_fs_proxy::send_container_list(const vector<sinsp_threadinfo*> &containers)
{
#ifndef CYGWING_AGENT
	sdc_internal::mounted_fs_request req;
	for(const auto& item : containers)
	{
		// Safety check, it should never happen
		if(item->m_root.empty())
		{
			g_logger.format(sinsp_logger::SEV_DEBUG, "Process root of pid %ld is empty, skipping ", item->m_pid);
			continue;
		}

		auto container = req.add_containers();
		container->set_id(item->m_container_id);
		container->set_pid(item->m_pid);
		container->set_vpid(item->m_vpid);
		container->set_root(item->m_root);
	}

	// Add host
	auto host = req.add_containers();
	host->set_id("host");
	host->set_pid(1U);
	host->set_vpid(1U);
	host->set_root("/");

	auto req_s = req.SerializeAsString();
	return m_output.send(req_s);
#else
	ASSERT(false);
	throw sinsp_exception("mounted_fs_proxy::send_container_list not implemented on Windows");
#endif
}

mounted_fs_reader::mounted_fs_reader(bool remotefs, const mount_points_filter_vec& filters, unsigned mounts_limit_size):
	m_mount_points(make_shared<mount_points_limits>(filters, mounts_limit_size)),
	m_remotefs(remotefs)
{
}

int mounted_fs_reader::open_ns_fd(int pid)
{
	char filename[SCAP_MAX_PATH_SIZE];
	snprintf(filename, sizeof(filename), "%s/proc/%d/ns/mnt", scap_get_host_root(), pid);
	return open(filename, O_RDONLY);
}

bool mounted_fs_reader::change_ns(int destpid)
{
#ifndef CYGWING_AGENT
	g_logger.format(sinsp_logger::SEV_DEBUG, "Set to ns pid %d", destpid);
	// Go to container mnt ns
	auto fd = open_ns_fd(destpid);
	if(fd <= 0)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "Cannot open namespace fd for pid=%d", destpid);
		return false;
	}
	if(setns(fd, CLONE_NEWNS) != 0)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "Cannot setns to pid=%d", destpid);
		close(fd);
		return false;
	}
	close(fd);
	return true;
#else
	ASSERT(false);
	throw sinsp_exception("mounted_fs_reader::change_ns not implemented on Windows");
#endif
}

#ifndef CYGWING_AGENT
int mounted_fs_reader::handle_mounted_fs_request(const char* root_dir, int home_fd,
	const sdc_internal::mounted_fs_request& request, sdc_internal::mounted_fs_response& response)
{
	std::unordered_set<dev_t> seen_devices;

	for(const auto& container_proto : request.containers())
	{
		// Go to container mnt ns
		if(!change_ns(container_proto.pid()))
		{
			continue;
		}
		try
		{
			if(container_proto.root() != "/")
			{
				g_logger.format(sinsp_logger::SEV_DEBUG, "chroot to: %s", container_proto.root().c_str());
				auto res = chroot(container_proto.root().c_str());
				if(res != 0)
				{
					throw sinsp_exception(string("chroot on ") + container_proto.root() + " failed: " + strerror(errno));
				}
			}
			char filename[SCAP_MAX_PATH_SIZE];
			// Use mtab if it's not a symlink to /proc/self/mounts
			// Because when entering a mount namespace, we don't have
			// a self entry on /proc
			struct stat mtab_stat;
			if(lstat("/etc/mtab", &mtab_stat) == 0 && !S_ISLNK(mtab_stat.st_mode))
			{
				snprintf(filename, sizeof(filename), "/etc/mtab");
			}
			else
			{
				snprintf(filename, sizeof(filename), "/proc/%lu/mounts", container_proto.vpid());
			}
			auto fs_list = get_mounted_fs_list(filename);
			auto container_mounts_proto = response.add_containers();
			container_mounts_proto->set_container_id(container_proto.id());
			for(const auto& fs : fs_list)
			{
				auto fsinfo = container_mounts_proto->add_mounts();
				fs.to_protobuf(fsinfo);
			}

			snprintf(filename, sizeof(filename), "/proc/%lu/mountinfo", container_proto.vpid());
			std::ifstream mountinfo(filename);
			if(!mountinfo)
			{
				throw sinsp_exception(std::string("error opening ") + filename + ": " + strerror(errno));
			}

			auto devices = read_mountinfo(mountinfo);

			for(const auto &dev : devices)
			{
				auto new_device = seen_devices.insert(dev.first);
				if(new_device.second)
				{
					auto dev_info = response.add_devices();
					dev_info->set_number(dev.first);
					dev_info->set_name(dev.second);
				}
			}
		}
		catch (const sinsp_exception& ex)
		{
			g_logger.format(sinsp_logger::SEV_DEBUG, "Exception for container=%s pid=%d, vpid=%d: %s", container_proto.id().c_str(), container_proto.pid(), container_proto.vpid(), ex.what());
		}
		// Back home
		if(setns(home_fd, CLONE_NEWNS) != 0)
		{
			g_logger.log("Error on setns home, exiting", sinsp_logger::SEV_ERROR);
			return ERROR_EXIT;
		}

		if (chroot(root_dir) < 0)
		{
			g_logger.log("Cannot set root directory.", sinsp_logger::SEV_ERROR);
			return ERROR_EXIT;
		}
		if (chdir("/") < 0)
		{
			g_logger.log("Cannot change to root directory.", sinsp_logger::SEV_ERROR);
			return ERROR_EXIT;
		}
	}

	return 0;
}

std::unordered_map<uint32_t, std::string> mounted_fs_reader::read_mountinfo(std::istream &mountinfo)
{
	std::unordered_map<uint32_t, std::string> dev_numbers;
	std::string buf_str;

	while(std::getline(mountinfo, buf_str))
	{
		uint32_t major, minor;
		char device[4096];
		char fs_type[4096];
		char mountpoint[4096];
		// 25 0 8:3 / / rw,relatime shared:1 - ext4 /dev/sda3 rw,errors=remount-ro,data=ordered
		// 152 25 0:45 / /mnt ro,relatime shared:130 - nfs 192.168.121.1:/volume ro,vers=3,...
		// 177 232 0:51 /sysrq-trigger /proc/sysrq-trigger ro,relatime - proc proc rw
		int ret;
		const char* buf = buf_str.c_str();
		if((ret = sscanf(buf, "%*d %*d %d:%d %*s %s", &major, &minor, mountpoint)) != 3)
		{
			g_logger.format(sinsp_logger::SEV_DEBUG, "Failed to get device number (ret=%d) from \"%s\"", ret, buf);
			continue;
		}
		const char *p = strstr(buf, " - ");
		if (!p)
		{
			g_logger.format(sinsp_logger::SEV_DEBUG, "Failed to find option separator in \"%s\"", buf);
			continue;
		}
		if((ret = sscanf(p, " - %s %s", fs_type, device)) != 2)
		{
			g_logger.format(sinsp_logger::SEV_DEBUG, "Failed to get device name (ret=%d) from \"%s\"", ret, buf);
			continue;
		}
		if (!m_mount_points->allow(device, fs_type, mountpoint))
		{
			continue;
		}

		dev_numbers.emplace(std::make_pair(makedev(major, minor), device));
	}

	return dev_numbers;
}
#endif

int mounted_fs_reader::run()
{
#ifndef CYGWING_AGENT
	auto pid = getpid();
	posix_queue input("/sdc_mounted_fs_reader_in", posix_queue::direction_t::RECEIVE);
	posix_queue output("/sdc_mounted_fs_reader_out", posix_queue::direction_t::SEND);

	g_logger.format(sinsp_logger::SEV_INFO, "Starting mounted_fs_reader with pid %u", pid);
	int home_fd = 0;
	if(getppid() == 1)
	{
		// If `--pid host` is not used, we take the mnt from /proc
		// as we don't know our hostpid
		char filename[SCAP_MAX_PATH_SIZE];
		snprintf(filename, sizeof(filename), "/proc/%d/ns/mnt", pid);
		home_fd = open(filename, O_RDONLY);
	}
	else
	{
		home_fd = open_ns_fd(pid);
	}

	if(home_fd <= 0)
	{
		return DONT_RESTART_EXIT;
	}

	// The procedure of traversing containers and their mounted file systems (the loop below) requires changing
	// namespace (and perhaps the root directory) of the agent/mounted_fs_reader to the one of a container. When examining
	// of a mounted file system is over, a step back to the home namespace and it's root directory is performed.
	// Executing `setns` to the home namespace together with `chroot` to the original root directory and then `chdir` is
	// sufficient in most cases to switch back.
	// However, there are situations like in case of Rkt containers when this is not good enough to break the root jail
	// (made by Rkt). To force jail break, there is an initial `setns` to the home namespace (which resets the root
	// directory) and then subsequent calls to `chroot` and `chdir` to set the real root directory. Since the purpose of
	// this trick is not obvious, it should be considered for refactoring in the future.

	if (setns(home_fd, CLONE_NEWNS) != 0)
	{
		g_logger.log("Error on setns home, exiting", sinsp_logger::SEV_ERROR);
		return ERROR_EXIT;
	};

	char root_dir[PATH_MAX];
	string root_dir_link = "/proc/" + to_string(getppid()) + "/root";
	ssize_t root_dir_sz = readlink(root_dir_link.c_str(), root_dir, PATH_MAX - 1);
	if (root_dir_sz <= 0)
	{
		g_logger.log("Cannot read root directory.", sinsp_logger::SEV_ERROR);
		return ERROR_EXIT;
	}
	else
		root_dir[root_dir_sz] = '\0';

	if (chroot(root_dir) < 0)
	{
		g_logger.log("Cannot set root directory.", sinsp_logger::SEV_ERROR);
		return ERROR_EXIT;
	}
	if (chdir("/") < 0)
	{
		g_logger.log("Cannot change to root directory.", sinsp_logger::SEV_ERROR);
		return ERROR_EXIT;
	}

	while(true)
	{
		// Send heartbeat
		send_subprocess_heartbeat();
		auto request_s = input.receive(1);
		if(request_s.empty())
		{
			continue;
		}

		sdc_internal::mounted_fs_request request_proto;
		if(!request_proto.ParseFromString(request_s))
		{
			continue;
		}

		sdc_internal::mounted_fs_response response_proto;
		g_logger.format(sinsp_logger::SEV_DEBUG, "Look mounted_fs for %d containers", request_proto.containers_size());
		// g_logger.format(sinsp_logger::SEV_DEBUG, "Receive from dragent; %s", request_proto.DebugString().c_str());

		int ret = handle_mounted_fs_request(root_dir, home_fd, request_proto, response_proto);
		if(ret != 0)
		{
			return ret;
		}

		auto response_s = response_proto.SerializeAsString();
		output.send(response_s);
	}
#else
	ASSERT(false);
	throw sinsp_exception("mounted_fs_reader::run not implemented on Windows");
#endif
}

vector<mounted_fs> mounted_fs_reader::get_mounted_fs_list(const string& mtab)
{
	map<string, mounted_fs> mount_points;

#if !defined(_WIN32) && !defined(CYGWING_AGENT)
	FILE* fp = setmntent(mtab.c_str(), "r");
	if(fp == NULL)
	{
		throw sinsp_exception("error opening " + mtab);
	}

	m_mount_points->reset();
	while(!m_mount_points->limit_is_reached())	// stops looking for more mount point entries when mount limit is reached
	{
		struct mntent* entry = getmntent(fp);
		if(entry == NULL)
		{
			break;
		}

		// already processed; skips
		if (mount_points.find(entry->mnt_dir) != mount_points.end())
		{
			continue;
		}

		bool colon_found = (strchr(entry->mnt_fsname, ':') != NULL);

		//
		// From coreutils, if dev contains ':', then remote
		//
		if(!m_remotefs)
		{
			// if remotefs are disabled, recognize them and skip
			if((colon_found && strstr(entry->mnt_fsname, "docker") == NULL)
			   || strcmp(entry->mnt_type, "nfs") == 0 // remote fs
			   || strcmp(entry->mnt_type, "smbfs") == 0
			   || strcmp(entry->mnt_type, "cifs") == 0)
			{
				continue;
			}
		}

		if (!m_mount_points->allow(entry->mnt_fsname, entry->mnt_type, entry->mnt_dir))
		{
			continue;
		}

		struct statvfs statfs;
		if(statvfs(entry->mnt_dir, &statfs) < 0)
		{
			g_logger.log("unable to get details for " + string(entry->mnt_dir) + ": " + strerror(errno), sinsp_logger::SEV_DEBUG);
			continue;
		}

		if(statfs.f_blocks == 0)
		{
			continue;
		}

		uint64_t blocksize;
		if(statfs.f_frsize)
		{
			blocksize = statfs.f_frsize;
		}
		else
		{
			blocksize = statfs.f_bsize;
		}


		m_mount_points->increase();

		mounted_fs fs;
		fs.device = entry->mnt_fsname;
		fs.mount_dir = entry->mnt_dir;
		fs.type =  entry->mnt_type;
		fs.available_bytes = blocksize * statfs.f_bavail;
		fs.size_bytes = blocksize * statfs.f_blocks;
		fs.used_bytes = blocksize * (statfs.f_blocks - statfs.f_bfree);
		fs.total_inodes = statfs.f_files;
		fs.used_inodes = statfs.f_files - statfs.f_ffree;
		mount_points[entry->mnt_dir] = move(fs);
	}

	endmntent(fp);

	m_mount_points->log_if_max_mount_limit_reached();
#else // !defined(_WIN32) && !defined(CYGWING_AGENT)
	#ifdef CYGWING_AGENT
	wh_mountlist mtable = wh_wmi_get_mounts(m_whhandle);
	if(mtable.m_result == 0)
	{
		throw sinsp_exception(string("error calling wh_wmi_get_mounts:") + wh_getlasterror(m_whhandle));
	}

	m_mount_points->reset();

	for(uint32_t j = 0; j < mtable.m_count; ++j)
	{
		wh_mounted_fs_info* wmi = &mtable.m_mounts[j];

		mounted_fs fs;
		fs.device = wmi->device;
		fs.mount_dir = wmi->mount_dir;
		fs.type =  wmi->type;
		fs.available_bytes = wmi->available_bytes;
		fs.size_bytes = wmi->size_bytes;
		fs.used_bytes = wmi->used_bytes;
		fs.total_inodes = 0;
		fs.used_inodes = 0;

		mount_points[fs.mount_dir] = move(fs);
	}
#endif // CYGWING_AGENT
#endif // !defined(_WIN32) && !defined(CYGWING_AGENT)
	vector<mounted_fs> ret;
	for (auto& mp : mount_points)
		ret.emplace_back(move(mp.second));
	return ret;
}

