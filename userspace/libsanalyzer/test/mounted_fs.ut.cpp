#include <gtest.h>

#define EXPOSE_INTERNALS_MOUNTED_FS_H

#include "sdc_internal.pb.h"
#include "mounted_fs.h"

class mounted_fs_test : public testing::Test {};

TEST_F(mounted_fs_test, get_mounted_fs_list_etc_mtab)
{
	mount_points_filter_vec filters({{"*|autofs|*", false}, {"*|proc|*", false}, {"*|subfs|*", false}, {"*|debugfs|*", false},
					 {"*|devpts|*", false}, {"*|fusectl|*", false}, {"*|mqueue|*", false}, {"*|rpc_pipefs|*", false},
					 {"*|sysfs|*", false}, {"*|devfs|*", false}, {"*|devtmpfs|*", false}, {"*|kernfs|*", false},
					 {"*|ignore|*", false}, {"*|rootfs|*", false}, {"*|none|*", false}, {"*|*|*", true}});

	mounted_fs_reader reader(false, filters, 15);
	vector<mounted_fs> fs_list = reader.get_mounted_fs_list();
	EXPECT_EQ(reader.get_limits()->get_filters().size(), filters.size());
	EXPECT_GE(fs_list.size(), 1u);
}

TEST_F(mounted_fs_test, get_mounted_fs_list) {
	char mtab[] = "/tmp/mtab.XXXXXX";

	mount_points_filter_vec filters({{"*|autofs|*", false}, {"*|proc|*", false}, {"*|subfs|*", false}, {"*|debugfs|*", false},
					 {"*|devpts|*", false}, {"*|fusectl|*", false}, {"*|mqueue|*", false}, {"*|rpc_pipefs|*", false},
					 {"*|sysfs|*", false}, {"*|devfs|*", false}, {"*|devtmpfs|*", false}, {"*|kernfs|*", false},
					 {"*|ignore|*", false}, {"*|rootfs|*", false}, {"*|none|*", false}, {"*|*|*", true}});

	const char* mtab_contents = "/dev/sda3 / ext4 rw,relatime,errors=remount-ro,data=ordered 0 0\n"
				    "/dev/sda1 /boot ext2 rw,relatime,data=ordered 0 0\n"
				    "192.168.121.1:/volume /mnt nfs ro,relatime,vers=3,rsize=1048576,wsize=1048576,"
				    "namlen=255,hard,proto=tcp,timeo=600,retrans=2,sec=sys,mountaddr=192.168.121.1,"
				    "mountvers=3,mountport=38524,mountproto=udp,local_lock=none,addr=192.168.121.1 0 0";
	int fd = mkstemp(mtab);
	EXPECT_EQ(strlen(mtab_contents), write(fd, mtab_contents, strlen(mtab_contents)));

	mounted_fs_reader reader(false, filters, 15);
	vector<mounted_fs> fs_list = reader.get_mounted_fs_list(mtab);

	auto num_fs = fs_list.size();
	EXPECT_EQ(2, num_fs);

	int num_found = 0;
	for(const auto& fs : fs_list)
	{
//		fprintf(stderr, "found %s on %s mounted at %s\n", fs.type.c_str(), fs.device.c_str(), fs.mount_dir.c_str());
		if (fs.device == "/dev/sda3")
		{
			EXPECT_EQ("/", fs.mount_dir);
			EXPECT_EQ("ext4", fs.type);
			num_found++;
		}
		else if (fs.device == "/dev/sda1")
		{
			EXPECT_EQ("/boot", fs.mount_dir);
			EXPECT_EQ("ext2", fs.type);
			num_found++;
		}
		EXPECT_GE(fs.size_bytes, fs.used_bytes);
		EXPECT_GE(fs.size_bytes, fs.available_bytes);
		EXPECT_GE(fs.size_bytes, fs.used_bytes + fs.available_bytes);
	}

	EXPECT_EQ(2, num_found);
	unlink(mtab);
}

TEST_F(mounted_fs_test, get_mounted_fs_list_remote) {
	char mtab[] = "/tmp/mtab.XXXXXX";

	mount_points_filter_vec filters({{"*|autofs|*", false}, {"*|proc|*", false}, {"*|subfs|*", false}, {"*|debugfs|*", false},
					 {"*|devpts|*", false}, {"*|fusectl|*", false}, {"*|mqueue|*", false}, {"*|rpc_pipefs|*", false},
					 {"*|sysfs|*", false}, {"*|devfs|*", false}, {"*|devtmpfs|*", false}, {"*|kernfs|*", false},
					 {"*|ignore|*", false}, {"*|rootfs|*", false}, {"*|none|*", false}, {"*|*|*", true}});

	const char* mtab_contents = "/dev/sda3 / ext4 rw,relatime,errors=remount-ro,data=ordered 0 0\n"
				    "/dev/sda1 /boot ext2 rw,relatime,data=ordered 0 0\n"
				    "192.168.121.1:/volume /mnt nfs ro,relatime,vers=3,rsize=1048576,wsize=1048576,"
				    "namlen=255,hard,proto=tcp,timeo=600,retrans=2,sec=sys,mountaddr=192.168.121.1,"
				    "mountvers=3,mountport=38524,mountproto=udp,local_lock=none,addr=192.168.121.1 0 0";
	int fd = mkstemp(mtab);
	EXPECT_EQ(strlen(mtab_contents), write(fd, mtab_contents, strlen(mtab_contents)));

	mounted_fs_reader reader(true, filters, 15);
	vector<mounted_fs> fs_list = reader.get_mounted_fs_list(mtab);

	auto num_fs = fs_list.size();
	EXPECT_EQ(3, num_fs);

	int num_found = 0;
	for(const auto& fs : fs_list)
	{
//		fprintf(stderr, "found %s on %s mounted at %s\n", fs.type.c_str(), fs.device.c_str(), fs.mount_dir.c_str());
		if (fs.device == "/dev/sda3")
		{
			EXPECT_EQ("/", fs.mount_dir);
			EXPECT_EQ("ext4", fs.type);
			num_found++;
		}
		else if (fs.device == "192.168.121.1:/volume")
		{
			EXPECT_EQ("/mnt", fs.mount_dir);
			EXPECT_EQ("nfs", fs.type);
			num_found++;
		}
		else if (fs.device == "/dev/sda1")
		{
			EXPECT_EQ("/boot", fs.mount_dir);
			EXPECT_EQ("ext2", fs.type);
			num_found++;
		}
		EXPECT_GE(fs.size_bytes, fs.used_bytes);
		EXPECT_GE(fs.size_bytes, fs.available_bytes);
		EXPECT_GE(fs.size_bytes, fs.used_bytes + fs.available_bytes);
	}

	EXPECT_EQ(3, num_found);
	unlink(mtab);
}

TEST_F(mounted_fs_test, read_mountinfo) {
	const std::string mountinfo =
		"19 25 0:18 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw\n"
		"20 25 0:4 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw\n"
		"21 25 0:6 / /dev rw,nosuid,relatime shared:2 - devtmpfs udev rw,size=12323272k,nr_inodes=3080818,mode=755\n"
		"22 21 0:14 / /dev/pts rw,nosuid,noexec,relatime shared:3 - devpts devpts rw,gid=5,mode=620,ptmxmode=000\n"
		"23 25 0:19 / /run rw,nosuid,noexec,relatime shared:5 - tmpfs tmpfs rw,size=2468876k,mode=755\n"
		"25 0 8:3 / / rw,relatime shared:1 - ext4 /dev/sda3 rw,errors=remount-ro,data=ordered\n"
		"26 19 0:12 / /sys/kernel/security rw,nosuid,nodev,noexec,relatime shared:8 - securityfs securityfs rw\n"
		"27 21 0:21 / /dev/shm rw,nosuid,nodev shared:4 - tmpfs tmpfs rw\n"
		"28 23 0:22 / /run/lock rw,nosuid,nodev,noexec,relatime shared:6 - tmpfs tmpfs rw,size=5120k\n"
		"29 19 0:23 / /sys/fs/cgroup ro,nosuid,nodev,noexec shared:9 - tmpfs tmpfs ro,mode=755\n"
		"30 29 0:24 / /sys/fs/cgroup/systemd rw,nosuid,nodev,noexec,relatime shared:10 - cgroup cgroup rw,xattr,release_agent=/lib/systemd/systemd-cgroups-agent,name=systemd\n"
		"31 19 0:25 / /sys/fs/pstore rw,nosuid,nodev,noexec,relatime shared:11 - pstore pstore rw\n"
		"32 29 0:26 / /sys/fs/cgroup/devices rw,nosuid,nodev,noexec,relatime shared:13 - cgroup cgroup rw,devices\n"
		"33 29 0:27 / /sys/fs/cgroup/blkio rw,nosuid,nodev,noexec,relatime shared:14 - cgroup cgroup rw,blkio\n"
		"34 29 0:28 / /sys/fs/cgroup/cpuset rw,nosuid,nodev,noexec,relatime shared:15 - cgroup cgroup rw,cpuset\n"
		"35 29 0:29 / /sys/fs/cgroup/freezer rw,nosuid,nodev,noexec,relatime shared:16 - cgroup cgroup rw,freezer\n"
		"36 29 0:30 / /sys/fs/cgroup/memory rw,nosuid,nodev,noexec,relatime shared:17 - cgroup cgroup rw,memory\n"
		"37 29 0:31 / /sys/fs/cgroup/pids rw,nosuid,nodev,noexec,relatime shared:18 - cgroup cgroup rw,pids\n"
		"38 29 0:32 / /sys/fs/cgroup/cpu,cpuacct rw,nosuid,nodev,noexec,relatime shared:19 - cgroup cgroup rw,cpu,cpuacct\n"
		"39 29 0:33 / /sys/fs/cgroup/net_cls,net_prio rw,nosuid,nodev,noexec,relatime shared:20 - cgroup cgroup rw,net_cls,net_prio\n"
		"40 29 0:34 / /sys/fs/cgroup/hugetlb rw,nosuid,nodev,noexec,relatime shared:21 - cgroup cgroup rw,hugetlb\n"
		"41 29 0:35 / /sys/fs/cgroup/perf_event rw,nosuid,nodev,noexec,relatime shared:22 - cgroup cgroup rw,perf_event\n"
		"42 20 0:36 / /proc/sys/fs/binfmt_misc rw,relatime shared:23 - autofs systemd-1 rw,fd=28,pgrp=1,timeout=0,minproto=5,maxproto=5,direct\n"
		"43 21 0:17 / /dev/mqueue rw,relatime shared:24 - mqueue mqueue rw\n"
		"45 19 0:7 / /sys/kernel/debug rw,relatime shared:25 - debugfs debugfs rw\n"
		"44 21 0:37 / /dev/hugepages rw,relatime shared:26 - hugetlbfs hugetlbfs rw\n"
		"46 23 0:38 / /run/rpc_pipefs rw,relatime shared:27 - rpc_pipefs sunrpc rw\n"
		"47 20 0:39 / /proc/fs/nfsd rw,relatime shared:28 - nfsd nfsd rw\n"
		"48 19 0:40 / /sys/fs/fuse/connections rw,relatime shared:29 - fusectl fusectl rw\n"
		"95 25 8:1 / /boot rw,relatime shared:75 - ext4 /dev/sda1 rw,data=ordered\n"
		"98 42 0:42 / /proc/sys/fs/binfmt_misc rw,relatime shared:78 - binfmt_misc binfmt_misc rw\n"
		"149 25 0:44 / /var/lib/lxcfs rw,nosuid,nodev,relatime shared:127 - fuse.lxcfs lxcfs rw,user_id=0,group_id=0,allow_other\n"
		"215 23 0:46 / /run/user/0 rw,nosuid,nodev,relatime shared:181 - tmpfs tmpfs rw,size=2468876k,mode=700\n"
		"231 23 0:19 /netns /run/netns rw,nosuid,noexec,relatime shared:5 - tmpfs tmpfs rw,size=2468876k,mode=755\n"
		"223 25 0:47 / /mnt ro,relatime shared:189 - nfs 192.168.121.1:/volume ro,vers=3,rsize=1048576,wsize=1048576,namlen=255,hard,proto=tcp,timeo=600,retrans=2,sec=sys,mountaddr=192.168.121.1,mountvers=3,mountport=38524,mountproto=udp,local_lock=none,addr=192.168.121.1\n"
		"227 45 0:9 / /sys/kernel/debug/tracing rw,relatime shared:196 - tracefs tracefs rw\n"
		"219 25 7:0 / /tmp/testquotamnt rw,relatime shared:185 - ext4 /dev/loop0 rw,quota,usrquota,grpquota,data=ordered\n"
		"235 25 0:48 / /var/lib/docker/overlay2/30bae6296804c375887e69c0b52aacc24b964d45f685ac87065e2f4c2ab110bf/merged rw,relatime shared:200 - overlay overlay rw,lowerdir=/var/lib/docker/overlay2/l/XVMLY3XQLBK2VHGMBTEBPDI3RD:/var/lib/docker/overlay2/l/26SUHUWL4OXWZL5HGD7EVIKO7M:/var/lib/docker/overlay2/l/37W22ZPSNXOWWINNQCRORIOPVN:/var/lib/docker/overlay2/l/FFA6H4UIJT5KLKOKMB2G5OKAMO:/var/lib/docker/overlay2/l/DOCN32G6HLSY4C6JASZLDRKHZQ:/var/lib/docker/overlay2/l/R2H6VVON4AT2AJMKHEW4TQLMHS:/var/lib/docker/overlay2/l/D2UUE5LLSYA5XFS3OY22AKAG6F:/var/lib/docker/overlay2/l/Y4GXUNXUD5UQ7XTIR4RKMRI53I:/var/lib/docker/overlay2/l/GSVTUIDUHVA433RSABMVK3H5OL:/var/lib/docker/overlay2/l/2BAYDI3EBJZIS5JTCP3VBPAUXH:/var/lib/docker/overlay2/l/RZWT74MDXQ35PDCANXQDJPK7K3:/var/lib/docker/overlay2/l/WXJPUSDWUOOSQGRKZW6Z5ZHFZY,upperdir=/var/lib/docker/overlay2/30bae6296804c375887e69c0b52aacc24b964d45f685ac87065e2f4c2ab110bf/diff,workdir=/var/lib/docker/overlay2/30bae6296804c375887e69c0b52aacc24b964d45f685ac87065e2f4c2ab110bf/work\n"
		"252 25 0:49 / /var/lib/docker/containers/af3740cf9a6b2f00f92897474a5337ef885fedb963179f2772cc35f1f334a0a8/mounts/shm rw,nosuid,nodev,noexec,relatime shared:204 - tmpfs shm rw,size=65536k\n"
		"327 23 0:3 net:[4026532321] /run/docker/netns/5f438c1468cf rw shared:208 - nsfs nsfs rw";

	mount_points_filter_vec filters({{"*|autofs|*", false}, {"*|proc|*", false}, {"*|subfs|*", false}, {"*|debugfs|*", false},
					 {"*|devpts|*", false}, {"*|fusectl|*", false}, {"*|mqueue|*", false}, {"*|rpc_pipefs|*", false},
					 {"*|sysfs|*", false}, {"*|devfs|*", false}, {"*|devtmpfs|*", false}, {"*|kernfs|*", false},
					 {"*|ignore|*", false}, {"*|rootfs|*", false}, {"*|none|*", false}, {"*|*|*", true}});

	std::istringstream iss(mountinfo);

	mounted_fs_reader reader(true, filters, 15);
	auto device_map = reader.read_mountinfo(iss);

	EXPECT_EQ("/dev/sda3", device_map[makedev(8, 3)]);
	EXPECT_EQ("/dev/loop0", device_map[makedev(7, 0)]);
	EXPECT_EQ("192.168.121.1:/volume", device_map[makedev(0, 47)]);

	EXPECT_EQ("", device_map[makedev(0, 4)]); // should be filtered out
}