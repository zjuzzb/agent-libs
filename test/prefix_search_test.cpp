#include <gtest.h>

#include <prefix_search.h>

using namespace std;

TEST(prefix_search_test, basic)
{
	path_prefix_search tree;

	tree.add_search_path("/var/run");
	tree.add_search_path("/etc/");
	tree.add_search_path("/lib");
	tree.add_search_path("/usr/lib");

	bool found = tree.match("/var/run/docker");
	ASSERT_TRUE(found);

	found = tree.match("/boot");
	ASSERT_FALSE(found);

	found = tree.match("/var/lib/messages");
	ASSERT_FALSE(found);

	found = tree.match("/var/lib/messages/");
	ASSERT_FALSE(found);

	found = tree.match("/var");
	ASSERT_FALSE(found);

	found = tree.match("/var/run");
	ASSERT_TRUE(found);
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
}
