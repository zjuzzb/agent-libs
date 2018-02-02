#include <gtest.h>

#include <prefix_search.h>
#include <security_policy.h>

using namespace std;

TEST(prefix_search_test, basic)
{
	path_prefix_search tree;

	tree.add_search_path("/var/run");
	tree.add_search_path("/var/run/dmesg");
	tree.add_search_path("/etc/");
	tree.add_search_path("/lib");
	tree.add_search_path("/usr/lib");
	tree.add_search_path("/usr/local");

	bool found = tree.match("/var/run/docker");
	ASSERT_TRUE(found);

	found = tree.match("/boot");
	ASSERT_FALSE(found);

	found = tree.match("/var/lib/messages");
	ASSERT_FALSE(found);

	found = tree.match("/var");
	ASSERT_FALSE(found);

	found = tree.match("/var/run");
	ASSERT_TRUE(found);

	found = tree.match("/usr");
	ASSERT_FALSE(found);
}

TEST(prefix_search_test, subpaths)
{
	path_prefix_search tree;

	tree.add_search_path("/var/log/messages");
	tree.add_search_path("/etc/");
	tree.add_search_path("/lib");
	tree.add_search_path("/usr/local/lib64");

	// Should expect to see the string 'lib64' in the output, as a
	// part of the directory /usr/local/lib64, and 'messages', via
	// /var/log/messages.
	string treerep = tree.as_string();
	ASSERT_TRUE(treerep.find("lib64") != string::npos);
	ASSERT_TRUE(treerep.find("messages") != string::npos);

	// Add a sibling of /usr/local/lib64, expect to find it
	tree.add_search_path("/usr/local/new");
	treerep = tree.as_string();
	ASSERT_TRUE(treerep.find("lib64") != string::npos);
	ASSERT_TRUE(treerep.find("new") != string::npos);

 	// Adding /usr/local will remove /usr/local/lib64 and
 	// /usr/local/new, as /usr/local is a prefix of both.
	tree.add_search_path("/usr/local");
	treerep = tree.as_string();
	ASSERT_TRUE(treerep.find("lib64") == string::npos);
	ASSERT_TRUE(treerep.find("new") == string::npos);

	// Adding /usr/local/lib64 again will result in no change, as
	// it is already covered by /usr/local
	tree.add_search_path("/usr/local/lib64");
	tree.add_search_path("/usr/local/new");
	treerep = tree.as_string();
	ASSERT_TRUE(treerep.find("lib64") == string::npos);
	ASSERT_TRUE(treerep.find("new") == string::npos);

	// Adding /usr will drop /usr/local
	tree.add_search_path("/usr");
	treerep = tree.as_string();
	ASSERT_TRUE(treerep.find("local") == string::npos);

	// Adding /var will drop /var/log/messages
	tree.add_search_path("/var");
	treerep = tree.as_string();
	ASSERT_TRUE(treerep.find("log") == string::npos);
	ASSERT_TRUE(treerep.find("messages") == string::npos);

	// Adding / will drop everything
	tree.add_search_path("/");
	treerep = tree.as_string();
	ASSERT_TRUE(treerep.find("var") == string::npos);
}

TEST(prefix_search_test, root_dir_match)
{
	path_prefix_search tree;
	tree.add_search_path("/");

	bool found = tree.match("/");
	ASSERT_TRUE(found);

	found = tree.match("/one");
	ASSERT_TRUE(found);

	found = tree.match("/one/two");
	ASSERT_TRUE(found);

	found = tree.match("/one/two/three");
	ASSERT_TRUE(found);
}

TEST(prefix_search_test, maps)
{
	path_prefix_map<uint32_t> tree;
	uint32_t val;
	const uint32_t *match;

	val=1;
	tree.add_search_path("/var/run", val);

	val=2;
	tree.add_search_path("/etc", val);

	val=3;
	tree.add_search_path("/lib", val);

	val=4;
	tree.add_search_path("/usr/lib", val);

	match = tree.match("/var/run/docker");
	ASSERT_TRUE(*match == 1);

	match = tree.match("/boot");
	ASSERT_TRUE(match == NULL);

	match = tree.match("/var/lib/messages");
	ASSERT_TRUE(match == NULL);

	match = tree.match("/var");
	ASSERT_TRUE(match == NULL);

	match = tree.match("/var/run");
	ASSERT_TRUE(*match == 1);

	match = tree.match("/usr");
	ASSERT_TRUE(match == NULL);

	match = tree.match("/etc");
	ASSERT_TRUE(*match == 2);

	match = tree.match("/lib");
	ASSERT_TRUE(*match == 3);

	match = tree.match("/usr/lib");
	ASSERT_TRUE(*match == 4);

	match = tree.match("/usr/lib/foo");
	ASSERT_TRUE(*match == 4);

//	std::cout << "***Before tree prefix add:" << std::endl;
//	std::cout << tree.as_string(true);

	val=5;
	tree.add_search_path("/usr", val);

	match = tree.match("/usr/lib/foo");
	ASSERT_TRUE(*match == 5);

//	std::cout << "***After tree prefix add:" << std::endl;
//	std::cout << tree.as_string(true);
}

TEST(prefix_search_test, root_dir_maps)
{
	path_prefix_map<uint32_t> tree;
	uint32_t val;
	const uint32_t *match;

	val = 1;
	tree.add_search_path("/etc", val);

	match = tree.match("/etc");
	ASSERT_TRUE(*match == 1);

	val = 2;
	tree.add_search_path("/", val);

	match = tree.match("/etc");
	ASSERT_TRUE(*match == 2);

	match = tree.match("/");
	ASSERT_TRUE(*match == 2);

	match = tree.match("/one");
	ASSERT_TRUE(*match == 2);

	match = tree.match("/owe/two");
	ASSERT_TRUE(*match == 2);

	match = tree.match("/one/two/three");
	ASSERT_TRUE(*match == 2);
}

struct container_split_testcase
{
	filter_value_t input;
	filter_value_t exp_hostname;
	filter_value_t exp_port;
	filter_value_t exp_imagename;
	filter_value_t exp_tag;
	filter_value_t exp_digest;
};

static filter_value_t empty = {(uint8_t *) "\0", 1};

static list<container_split_testcase> container_split_testcases = {
	{{(uint8_t *) "busybox", 7},empty,empty,{(uint8_t *) "busybox", 7},empty,empty},
	{{(uint8_t *) "busybox:latest", 14},empty,empty,{(uint8_t *) "busybox", 7},{(uint8_t *) "latest", 6},empty},
	{{(uint8_t *) "busybox:1.27.2@sha256:bbc3a03", 29},empty,empty,{(uint8_t *) "busybox", 7},{(uint8_t *) "1.27.2",6},{(uint8_t *)"sha256:bbc3a03", 14}},
	{{(uint8_t *) "my.host.name/busybox:1.27.2@sha256:bbc3a03", 42},{(uint8_t *) "my.host.name", 12},empty,{(uint8_t *) "busybox", 7},{(uint8_t *) "1.27.2",6},{(uint8_t *)"sha256:bbc3a03", 14}},
	{{(uint8_t *) "my.host.name:12345/library/busybox:1.27.2@sha256:bbc3a03", 56},{(uint8_t *) "my.host.name", 12},{(uint8_t *) "12345", 5},{(uint8_t *) "library/busybox", 15},{(uint8_t *) "1.27.2",6},{(uint8_t *)"sha256:bbc3a03", 14}},
	{{(uint8_t *) "localhost:12345/library/busybox:1.27.2@sha256:bbc3a03", 53},{(uint8_t *) "localhost", 9},{(uint8_t *) "12345", 5},{(uint8_t *) "library/busybox", 15},{(uint8_t *) "1.27.2",6},{(uint8_t *)"sha256:bbc3a03", 14}}
};

#define CHECK_FILTER_VALUE(name, actual, expected) ASSERT_TRUE(comp(actual, expected)) << "Expected " << name " '" << string((char *) expected.first, expected.second) << "' did not match actual value '" << string((char *) actual.first, actual.second) << "'"

TEST(prefix_search_test, container_splitting)
{
	g_equal_to_membuf comp;

	for(auto &testcase : container_split_testcases)
	{
		filter_value_t hostname;
		filter_value_t port;
		filter_value_t imagename;
		filter_value_t tag;
		filter_value_t digest;

		path_prefix_map_ut::split_container_image(testcase.input,
							  hostname, port,
							  imagename,
							  tag, digest);
		CHECK_FILTER_VALUE("hostname", hostname, testcase.exp_hostname);
		CHECK_FILTER_VALUE("port", port, testcase.exp_port);
		CHECK_FILTER_VALUE("image name", imagename, testcase.exp_imagename);
		CHECK_FILTER_VALUE("tag", tag, testcase.exp_tag);
		CHECK_FILTER_VALUE("digest", digest, testcase.exp_digest);
	}
}

TEST(prefix_search_test, container_images)
{
	path_prefix_map<uint32_t> tree;
	uint32_t val;
	const uint32_t *match;

	val=1;
	path_prefix_map_ut::filter_components_t comp;
	comp.emplace_back(make_pair((uint8_t*)"my.domain.name", sizeof("my.domain.name")));
	comp.emplace_back(make_pair((uint8_t*)"12345", sizeof("12345")));
	tree.add_search_path_components(comp, val);
	comp.clear();

	val=2;
	comp.emplace_back(make_pair((uint8_t*)"\0", 1));
	comp.emplace_back(make_pair((uint8_t*)"\0", 1));
	comp.emplace_back(make_pair((uint8_t*)"busybox", sizeof("busybox")));
	tree.add_search_path_components(comp, val);
	comp.clear();

	val=3;
	comp.emplace_back(make_pair((uint8_t*)"\0", 1));
	comp.emplace_back(make_pair((uint8_t*)"\0", 1));
	comp.emplace_back(make_pair((uint8_t*)"alpine", sizeof("alpine")));
	tree.add_search_path_components(comp, val);
	comp.clear();

	val=4;
	comp.emplace_back(make_pair((uint8_t*)"sysdig", sizeof("sysdig")));
	comp.emplace_back(make_pair((uint8_t*)"\0", 1));
	comp.emplace_back(make_pair((uint8_t*)"agent", sizeof("agent")));
	tree.add_search_path_components(comp, val);
	comp.clear();

	path_prefix_map_ut::filter_components_t test;
	test.emplace_back(make_pair((uint8_t*)"my.domain.name", sizeof("my.domain.name")));
	test.emplace_back(make_pair((uint8_t*)"12345", sizeof("12345")));
	test.emplace_back(make_pair((uint8_t*)"busybox", sizeof("busybox")));
	test.emplace_back(make_pair((uint8_t*)"1.27.2", sizeof("1.27.2")));
	match = tree.match_components(test);
	test.clear();
	ASSERT_TRUE(*match == 1);

	test.emplace_back(make_pair((uint8_t*)"\0", 1));
	test.emplace_back(make_pair((uint8_t*)"\0", 1));
	test.emplace_back(make_pair((uint8_t*)"busybox", sizeof("busybox")));
	test.emplace_back(make_pair((uint8_t*)"1.27.2", sizeof("1.27.2")));
	match = tree.match_components(test);
	test.clear();
	ASSERT_TRUE(*match == 2);

	test.emplace_back(make_pair((uint8_t*)"\0", 1));
	test.emplace_back(make_pair((uint8_t*)"\0", 1));
	test.emplace_back(make_pair((uint8_t*)"alpine", sizeof("alpine")));
	test.emplace_back(make_pair((uint8_t*)"latest", sizeof("latest")));
	match = tree.match_components(test);
	test.clear();
	ASSERT_TRUE(*match == 3);

	test.emplace_back(make_pair((uint8_t*)"sysdig", sizeof("sysdig")));
	test.emplace_back(make_pair((uint8_t*)"\0", 1));
	test.emplace_back(make_pair((uint8_t*)"agent", sizeof("agent")));
	test.emplace_back(make_pair((uint8_t*)"\0", 1));
	test.emplace_back(make_pair((uint8_t*)"@sha256:aaaaaaaa", sizeof("@sha256:aaaaaaaa")));
	match = tree.match_components(test);
	test.clear();
	ASSERT_TRUE(*match == 4);
}
