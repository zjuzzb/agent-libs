#include <gtest.h>

#include <sinsp.h>
#include <fdinfo.h>
#include <dns_manager.h>

#include <fstream>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace std;

class dns_manager_test : public testing::Test
{
protected:
	virtual void SetUp()
	{
		struct stat s;
		ASSERT_TRUE(stat("/etc/hosts", &s) == 0);
		hosts_size = s.st_size;

		sinsp_dns_manager::get().set_base_refresh_timeout(2 * ONE_SECOND_IN_NS);
		sinsp_dns_manager::get().set_max_refresh_timeout(6 * ONE_SECOND_IN_NS);
		sinsp_dns_manager::get().set_erase_timeout(8 * ONE_SECOND_IN_NS);
	}

	virtual void TearDown()
	{
		sinsp_dns_manager::get().cleanup();
	}

	off_t hosts_size;
};

TEST_F(dns_manager_test, add_sync_remove)
{
	std::ofstream hosts;
	hosts.open("/etc/hosts",
		   std::fstream::binary |
		   std::fstream::in |
		   std::fstream::out |
		   std::fstream::ate);
	ASSERT_TRUE(hosts.is_open());

	auto pos = hosts.tellp();

	hosts.write("\n0.0.0.1 afakefqdn\n::2 afakev6fqdn\n", sizeof("\n0.0.0.1 afakefqdn\n::2 afakev6fqdn\n"));
	hosts.flush();

	uint32_t addr4;
	uint32_t addr6[4];
	inet_pton(AF_INET, "0.0.0.1", &addr4);
	inet_pton(AF_INET6, "::2", &addr6[0]);

	sinsp_dns_manager &m = sinsp_dns_manager::get();
	
	bool res = m.match("afakefqdn", AF_INET, &addr4, sinsp_utils::get_current_time_ns());
	res &= m.match("afakev6fqdn", AF_INET6, &addr6[0], sinsp_utils::get_current_time_ns());
	ASSERT_TRUE(res);

	// change the resolved addresses
	hosts.seekp(pos);
	hosts.write("\n0.0.0.2 afakefqdn\n::3 afakev6fqdn\n", sizeof("\n0.0.0.2 afakefqdn\n::3 afakev6fqdn\n"));
	hosts.flush();

	// now 0.0.0.1 and ::2 shouldn't match anymore
	// Keep trying for up to 8 seconds (it can take a while for the DNS cache to refresh)
	int num_tries = 8;
	do {
		sleep(1);
		res = m.match("afakefqdn", AF_INET, &addr4, sinsp_utils::get_current_time_ns());
		res |= m.match("afakev6fqdn", AF_INET6, &addr6[0], sinsp_utils::get_current_time_ns());
		--num_tries;
	} while (res && num_tries > 0);
	ASSERT_TRUE(!res);

	// 0.0.0.2 and ::3 should instead match now
	inet_pton(AF_INET, "0.0.0.2", &addr4);
	inet_pton(AF_INET6, "::3", &addr6[0]);
	res = m.match("afakefqdn", AF_INET, &addr4, sinsp_utils::get_current_time_ns());
	res &= m.match("afakev6fqdn", AF_INET6, &addr6[0], sinsp_utils::get_current_time_ns());
	ASSERT_TRUE(res);

	// Should take 8 seconds to erase. Keep checking for up to 14 seconds because Jenkins.
	num_tries = 14;
	do {
		sleep(1);
		--num_tries;
	} while (num_tries > 0 && m.size() > 0);
	ASSERT_EQ(m.size(), 0);

	hosts.close();

	ASSERT_TRUE(truncate("/etc/hosts", hosts_size) == 0);
}
