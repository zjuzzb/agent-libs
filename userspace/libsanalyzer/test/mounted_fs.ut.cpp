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

