#include <dns_manager.h>
#include <fstream>
#include <gtest.h>
#include <sinsp.h>
#include <unordered_set>
#include <tbb/concurrent_unordered_set.h>
#include <random>

using namespace std;

class dns_manager_test : public testing::Test
{
protected:
	virtual void SetUp()
	{
		struct stat s;
		hosts_size = 0; // make sure we have a sane exit path
		ASSERT_TRUE(stat("/etc/hosts", &s) == 0);
		hosts_size = s.st_size;

		sinsp_dns_manager::get().set_base_refresh_timeout(ONE_SECOND_IN_NS * 1);
		sinsp_dns_manager::get().set_max_refresh_timeout(2 * ONE_SECOND_IN_NS);
		sinsp_dns_manager::get().set_erase_timeout(4 * ONE_SECOND_IN_NS);
	}

	virtual void TearDown()
	{
		sinsp_dns_manager::get().cleanup();
		// Clean up (i.e. truncate) /etc/hosts file
		// but only do so when we're sure we actually read its size
		if (hosts_size > 0)
		{
			ASSERT_TRUE(truncate("/etc/hosts", hosts_size) == 0);
		}
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
	const int max_tries = 15; // 15 secs
	int num_tries = max_tries;
	while (num_tries > 0) {
		std::this_thread::sleep_for (std::chrono::milliseconds (500));
		res = m.match("afakefqdn", AF_INET, &addr4, sinsp_utils::get_current_time_ns());
		res |= m.match("afakev6fqdn", AF_INET6, &addr6[0], sinsp_utils::get_current_time_ns());
		if (!res)
		{
			break;
		}
		--num_tries;
	}
	ASSERT_TRUE(!res);

	// 0.0.0.2 and ::3 should instead match now
	inet_pton(AF_INET, "0.0.0.2", &addr4);
	inet_pton(AF_INET6, "::3", &addr6[0]);
	res = m.match("afakefqdn", AF_INET, &addr4, sinsp_utils::get_current_time_ns());
	res &= m.match("afakev6fqdn", AF_INET6, &addr6[0], sinsp_utils::get_current_time_ns());
	ASSERT_TRUE(res);

	// Should take 8 seconds to erase. Keep checking for up to 16 seconds because Jenkins.
	num_tries = 4;
	do {
		sleep(4);
		--num_tries;
	} while (num_tries > 0 && m.size() > 0);
	ASSERT_EQ(m.size(), 0);

	hosts.close();

	ASSERT_TRUE(truncate("/etc/hosts", hosts_size) == 0);
	sinsp_dns_manager::get().cleanup();
}

TEST_F(dns_manager_test, add_sync_clear)
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

	// clear cache
	m.clear_cache();
	res = m.match("afakefqdn", AF_INET, &addr4, sinsp_utils::get_current_time_ns());
	res |= m.match("afakev6fqdn", AF_INET6, &addr6[0], sinsp_utils::get_current_time_ns());
	ASSERT_TRUE(!res);

	// 0.0.0.2 and ::3 should instead match now
	inet_pton(AF_INET, "0.0.0.2", &addr4);
	inet_pton(AF_INET6, "::3", &addr6[0]);
	res = m.match("afakefqdn", AF_INET, &addr4, sinsp_utils::get_current_time_ns());
	res &= m.match("afakev6fqdn", AF_INET6, &addr6[0], sinsp_utils::get_current_time_ns());
	ASSERT_TRUE(res);

	// Should take 8 seconds to erase. Keep checking for up to 16 seconds because Jenkins.
	auto num_tries = 4;
	do {
		sleep(4);
		--num_tries;
	} while (num_tries > 0 && m.size() > 0);
	ASSERT_EQ(m.size(), 0);

	hosts.close();

	ASSERT_TRUE(truncate("/etc/hosts", hosts_size) == 0);
	sinsp_dns_manager::get().cleanup();
}

TEST_F(dns_manager_test, stress_async_clear)
{
	const char* ipv6[] = {
	    "64c:441f:a1ee:a17b:5f2d:421b:473f:47ad",  "507a:f3b0:f8d7:c90c:e2fd:b209:5037:3dcc",
	    "2b14:4c22:10e8:8a71:d10:5c7c:e2f2:b51f",  "6834:ca92:e7bd:5671:1bba:bcc5:e4b8:eea4",
	    "1560:4019:c33e:c996:c293:6651:8001:5187", "aea1:33e9:d4eb:c983:9293:41fc:a5ad:e58a",
	    "7a12:b4c2:b17f:205b:898:2a2f:5f89:872d",  "5191:eab:146d:4ca7:55c6:9d37:d346:6dd7",
	    "8f6b:2d4c:77fc:609f:8f31:e926:6c47:4a56", "c5ad:ff73:29ca:afe9:7e17:6d93:f039:c0c5",
	    "9d98:fb58:1d3e:e093:7f9a:90e7:cd76:1a90", "ced9:6965:b710:c7b1:309a:9c3:a46c:90b0",
	    "ab6c:578a:a965:39df:cf16:58c8:e085:aab7", "1bef:1932:fa88:3217:8f41:5023:f621:f99d",
	    "f4c4:8568:55e3:3d79:9ac2:91ce:168f:86a0", "b3a9:3dfd:d0ee:c17f:7d75:1917:fd8e:b8c3",
	    "2e28:8d07:1620:1a30:556:4aa7:1dc7:3575",  "b9ea:3f90:8518:55a6:d9dc:306:5270:9ce6",
	    "dc5a:641e:e3b4:113:2044:f1b0:8ff8:8844",  "3e02:e7dc:d651:f25:7cbf:b537:272c:7318",
	    "7ca1:ade4:648a:ef8:bc6b:c077:6b9d:5ad9",  "5f18:7c33:b791:8997:2e2b:b290:1efe:1551",
	    "749:270d:8fb0:7a1:249f:fe31:d24a:e908",   "745d:753a:11b2:bce0:f0f6:962b:e0b7:ff6c",
	    "e62a:328c:a6e0:ad08:aa8c:80b8:5948:11c4", "6214:eb0a:8f6c:b3c0:33d8:fda2:b61e:31b7",
	    "31b8:fc90:d090:8ed5:a9cf:69e0:d4ff:639c", "2ca4:5c0:7463:734e:891a:cc1b:c821:70c8",
	    "d84b:5950:7683:18da:f317:cf24:b402:46d1", "2853:ec2e:8b9a:5dc7:eff6:df18:360e:e9be",
	    "b92f:5277:e466:2e73:8a56:ce1f:bd6d:3720", "1e7f:9764:c37f:3683:9da5:83eb:5fed:d01b",
	    "b8d3:2888:3f3e:f8b4:3ba4:cb83:a0b1:5c16", "234d:4ebf:41f:913e:b8de:4954:bbf8:6546",
	    "3e65:c624:5c1e:8eef:6be8:9b95:f1fa:6397", "c67a:deb0:58d3:f28f:2ff4:2b5d:e1fe:3cb7",
	    "c2f0:8938:948d:11e3:1215:39d1:d565:2391", "eebc:fe58:d84a:1201:5bae:da96:e058:5ae1",
	    "f326:d554:2de0:af94:d763:743d:bdca:34ed", "f145:b1fb:d161:472e:4145:7406:618b:9749"};

	const char* ipv4[] = {
	    "182.105.114.16",  "65.190.61.68",   "88.119.70.8",     "79.255.122.164", "12.116.97.53",
	    "51.48.209.165",   "250.220.199.72", "215.109.242.136", "213.131.1.81",   "99.36.124.157",
	    "24.174.14.187",   "41.95.41.125",   "175.210.235.170", "57.174.250.20",  "151.195.150.242",
	    "15.240.202.190",  "183.203.136.55", "204.128.130.214", "226.166.23.74",  "212.77.6.49",
	    "178.228.14.92",   "197.149.2.4",    "98.131.111.53",   "70.34.84.215",   "95.79.15.137",
	    "221.218.210.198", "136.208.89.213", "145.104.221.74",  "226.215.99.28",  "143.2.199.119",
	    "58.193.93.232",   "244.216.25.155", "228.92.139.207",  "50.192.7.243",   "13.201.44.44",
	    "11.8.19.54",      "45.0.59.178",    "174.76.122.134",  "192.100.201.177","192.100.201.177"};

	std::ofstream hosts;
	hosts.open("/etc/hosts",
	           std::fstream::binary |
	               std::fstream::in |
	               std::fstream::out |
	               std::fstream::ate);
	ASSERT_TRUE(hosts.is_open());

	hosts << "\n";

	using ip_to_name=std::vector<std::pair<std::string, std::string>>;
	ip_to_name ip4name;
	ip_to_name ip6name;
	using name_to_ip=tbb::concurrent_unordered_set<std::pair<std::string, std::string>>;
	name_to_ip name4ip;
	name_to_ip name6ip;

	for (int i = 0; i < 400; ++i)
	{
		auto ip = i % 40;
		auto iname = ip % 8;

		std::string n6 = ipv6[iname];
		std::replace(n6.begin(), n6.end(), ':', '_');
		std::string n4 = ipv4[iname];
		std::replace(n4.begin(), n4.end(), '.', '_');
		hosts << std::string(ipv6[iname]) << " " << n6 << "\n"
		      << std::string(ipv4[iname]) << " " << n4 << "\n";

		ip4name.emplace_back(ipv4[iname], n4);
		name4ip.emplace(n4, ipv4[iname]);

		ip6name.emplace_back(ipv6[iname], n6);
		name6ip.emplace(n6, ipv6[iname]);
	}

	hosts.flush();

	std::atomic <bool> exit_flag;
	exit_flag.store(false);

	auto match = [&] ()
	{
		std::random_device rd;
		std::uniform_int_distribution<uint64_t> dist(0, 399);

		auto  &m = sinsp_dns_manager::get();
		while (!exit_flag.load())
		{
			uint64_t ts = sinsp_utils::get_current_time_ns();
			uint32_t addr4;
			uint32_t addr6[4];
			auto idx = dist(rd);
			auto rec4 = ip4name[idx];
			auto rec6 = ip6name[idx];

			inet_pton(AF_INET, rec4.first.c_str(), &addr4);
			inet_pton(AF_INET6, rec6.first.c_str(), &addr6[0]);

			ASSERT_TRUE(m.match(rec4.second.c_str(), AF_INET, &addr4, ts));
			auto n = m.name_of(AF_INET, &addr4, ts);
			if ( !n.empty() )
			{
				ASSERT_FALSE(name4ip.find( std::make_pair(n, rec4.first)) == name4ip.end());
			}

			ASSERT_TRUE(m.match(rec6.second.c_str(), AF_INET6, &addr6[0], ts));
			n = m.name_of(AF_INET6, &addr6[0], ts);
			if ( !n.empty() )
			{
				if (name6ip.find( std::make_pair(n, rec6.first)) == name6ip.end())
				{
					std::cout << "\tn=" << n << " f=" << rec6.first << " s=" << rec6.first;
				}
				ASSERT_FALSE(name6ip.find( std::make_pair(n, rec6.first)) == name6ip.end());
			}

			std::this_thread::sleep_for (std::chrono::milliseconds (idx/5+1));
		}
	};

	auto clear_cache = [&]()
	{
		std::random_device rd;
		std::uniform_int_distribution<uint64_t> dist(0, 399);

		auto  &m = sinsp_dns_manager::get();
		while (!exit_flag.load())
		{
			m.clear_cache();
			auto idx = dist(rd);
			std::this_thread::sleep_for (std::chrono::milliseconds (idx+1));
		}
	};

	auto m_resolver1 = thread(match);
	auto m_resolver2 = thread(match);
	auto m_resolver3 = thread(clear_cache);

	std::this_thread::sleep_for (std::chrono::seconds (10));

	exit_flag.store(true);

	if (m_resolver1.joinable())
		m_resolver1.join();

	if (m_resolver2.joinable())
		m_resolver2.join();

	if (m_resolver3.joinable())
		m_resolver3.join();

	hosts.close();

	ASSERT_TRUE(truncate("/etc/hosts", hosts_size) == 0);

	sinsp_dns_manager::get().cleanup();
}


TEST_F(dns_manager_test, stress_async_clear1)
{
	const char* ipv6[] = {
	    "64c:441f:a1ee:a17b:5f2d:421b:473f:47ad",  "507a:f3b0:f8d7:c90c:e2fd:b209:5037:3dcc",
	    "2b14:4c22:10e8:8a71:d10:5c7c:e2f2:b51f",  "6834:ca92:e7bd:5671:1bba:bcc5:e4b8:eea4",
	    "1560:4019:c33e:c996:c293:6651:8001:5187", "aea1:33e9:d4eb:c983:9293:41fc:a5ad:e58a",
	    "7a12:b4c2:b17f:205b:898:2a2f:5f89:872d",  "5191:eab:146d:4ca7:55c6:9d37:d346:6dd7",
	    "8f6b:2d4c:77fc:609f:8f31:e926:6c47:4a56", "c5ad:ff73:29ca:afe9:7e17:6d93:f039:c0c5",
	    "9d98:fb58:1d3e:e093:7f9a:90e7:cd76:1a90", "ced9:6965:b710:c7b1:309a:9c3:a46c:90b0",
	    "ab6c:578a:a965:39df:cf16:58c8:e085:aab7", "1bef:1932:fa88:3217:8f41:5023:f621:f99d",
	    "f4c4:8568:55e3:3d79:9ac2:91ce:168f:86a0", "b3a9:3dfd:d0ee:c17f:7d75:1917:fd8e:b8c3",
	    "2e28:8d07:1620:1a30:556:4aa7:1dc7:3575",  "b9ea:3f90:8518:55a6:d9dc:306:5270:9ce6",
	    "dc5a:641e:e3b4:113:2044:f1b0:8ff8:8844",  "3e02:e7dc:d651:f25:7cbf:b537:272c:7318",
	    "7ca1:ade4:648a:ef8:bc6b:c077:6b9d:5ad9",  "5f18:7c33:b791:8997:2e2b:b290:1efe:1551",
	    "749:270d:8fb0:7a1:249f:fe31:d24a:e908",   "745d:753a:11b2:bce0:f0f6:962b:e0b7:ff6c",
	    "e62a:328c:a6e0:ad08:aa8c:80b8:5948:11c4", "6214:eb0a:8f6c:b3c0:33d8:fda2:b61e:31b7",
	    "31b8:fc90:d090:8ed5:a9cf:69e0:d4ff:639c", "2ca4:5c0:7463:734e:891a:cc1b:c821:70c8",
	    "d84b:5950:7683:18da:f317:cf24:b402:46d1", "2853:ec2e:8b9a:5dc7:eff6:df18:360e:e9be",
	    "b92f:5277:e466:2e73:8a56:ce1f:bd6d:3720", "1e7f:9764:c37f:3683:9da5:83eb:5fed:d01b",
	    "b8d3:2888:3f3e:f8b4:3ba4:cb83:a0b1:5c16", "234d:4ebf:41f:913e:b8de:4954:bbf8:6546",
	    "3e65:c624:5c1e:8eef:6be8:9b95:f1fa:6397", "c67a:deb0:58d3:f28f:2ff4:2b5d:e1fe:3cb7",
	    "c2f0:8938:948d:11e3:1215:39d1:d565:2391", "eebc:fe58:d84a:1201:5bae:da96:e058:5ae1",
	    "f326:d554:2de0:af94:d763:743d:bdca:34ed", "f145:b1fb:d161:472e:4145:7406:618b:9749"};

	const char* ipv4[] = {
	    "182.105.114.16",  "65.190.61.68",   "88.119.70.8",     "79.255.122.164", "12.116.97.53",
	    "51.48.209.165",   "250.220.199.72", "215.109.242.136", "213.131.1.81",   "99.36.124.157",
	    "24.174.14.187",   "41.95.41.125",   "175.210.235.170", "57.174.250.20",  "151.195.150.242",
	    "15.240.202.190",  "183.203.136.55", "204.128.130.214", "226.166.23.74",  "212.77.6.49",
	    "178.228.14.92",   "197.149.2.4",    "98.131.111.53",   "70.34.84.215",   "95.79.15.137",
	    "221.218.210.198", "136.208.89.213", "145.104.221.74",  "226.215.99.28",  "143.2.199.119",
	    "58.193.93.232",   "244.216.25.155", "228.92.139.207",  "50.192.7.243",   "13.201.44.44",
	    "11.8.19.54",      "45.0.59.178",    "174.76.122.134",  "192.100.201.177", "192.100.201.178"};

	std::ofstream hosts;
	hosts.open("/etc/hosts",
	           std::fstream::binary |
	               std::fstream::in |
	               std::fstream::out |
	               std::fstream::ate);
	ASSERT_TRUE(hosts.is_open());

	hosts << "\n";

	using ip_to_name=std::vector<std::pair<std::string, std::string>>;
	ip_to_name ip4name;
	ip_to_name ip6name;
	using name_to_ip=tbb::concurrent_unordered_set<std::pair<std::string, std::string>>;
	name_to_ip name4ip;
	name_to_ip name6ip;

	for (int i = 0; i < 400; ++i)
	{
		auto ip = i % 40;
		auto iname =  ip / 8;

		std::string n6 = ipv6[iname];
		std::replace(n6.begin(), n6.end(), ':', '_');

		std::string n4 = ipv4[iname];
		std::replace(n4.begin(), n4.end(), '.', '_');

		hosts << std::string(ipv6[ip]) << " " << n6 << "\n"
		      << std::string(ipv4[ip]) << " " << n4 << "\n";

		ip4name.emplace_back(ipv4[ip], n4);
		name4ip.emplace(n4, ipv4[ip]);

		ip6name.emplace_back(ipv6[ip], n6);
		name6ip.emplace(n6, ipv6[ip]);
	}
	hosts.flush();

	std::atomic <bool> exit_flag;
	exit_flag.store(false);

	auto match = [&] ()
	{
		std::random_device rd;
		std::uniform_int_distribution<uint64_t> dist(0, 399);

		auto  &m = sinsp_dns_manager::get();
		while (!exit_flag.load())
		{
			uint64_t ts = sinsp_utils::get_current_time_ns();
			uint32_t addr4;
			uint32_t addr6[4];
			auto idx = dist(rd);
			auto rec4 = ip4name[idx];
			auto rec6 = ip6name[idx];

			inet_pton(AF_INET, rec4.first.c_str(), &addr4);
			inet_pton(AF_INET6, rec6.first.c_str(), &addr6[0]);

			ASSERT_TRUE(m.match(rec4.second.c_str(), AF_INET, &addr4, ts));
			auto n = m.name_of(AF_INET, &addr4, ts);
			if ( !n.empty() )
			{
				ASSERT_FALSE(name4ip.find( std::make_pair(n, rec4.first)) == name4ip.end());
			}

			ASSERT_TRUE(m.match(rec6.second.c_str(), AF_INET6, &addr6[0], ts));
			n = m.name_of(AF_INET6, &addr6[0], ts);
			if ( !n.empty() )
			{
				if (name6ip.find( std::make_pair(n, rec6.first)) == name6ip.end())
				{
					std::cout << "\tn=" << n << " f=" << rec6.first << " s=" << rec6.first;
				}
				ASSERT_FALSE(name6ip.find( std::make_pair(n, rec6.first)) == name6ip.end());
			}

			std::this_thread::sleep_for (std::chrono::milliseconds (idx/5+1));
		}
	};

	auto clear_cache = [&]()
	{
		std::random_device rd;
		std::uniform_int_distribution<uint64_t> dist(0, 399);

		auto  &m = sinsp_dns_manager::get();
		while (!exit_flag.load())
		{
			m.clear_cache();
			auto idx = dist(rd);
			std::this_thread::sleep_for (std::chrono::milliseconds (idx+1));
		}
	};

	auto m_resolver1 = thread(match);
	auto m_resolver2 = thread(match);
	auto m_resolver3 = thread(clear_cache);

	std::this_thread::sleep_for (std::chrono::seconds (10));

	exit_flag.store(true);

	if (m_resolver1.joinable())
		m_resolver1.join();

	if (m_resolver2.joinable())
		m_resolver2.join();

	if (m_resolver3.joinable())
		m_resolver3.join();

	hosts.close();

	ASSERT_TRUE(truncate("/etc/hosts", hosts_size) == 0);

	sinsp_dns_manager::get().cleanup();
}
