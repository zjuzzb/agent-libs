#include <gtest.h>

#include <utils.h>

#include <string>
#include <list>

using namespace std;

static list<vector<string>> with_splitting_testcases = {
//	 input                                                                                        host            port     name               tag       digest
	{"busybox"                                                                                  , ""            , ""     , "busybox"        , ""      , ""                                               },
	{"busybox:latest"                                                                           , ""            , ""     , "busybox"        , "latest", ""                                               },
	{"busybox:1.27.2@sha256:da39a3ee5e6b4b0d3255bfef95601890afd80709"                           , ""            , ""     , "busybox"        , "1.27.2", "sha256:da39a3ee5e6b4b0d3255bfef95601890afd80709"},
	{"my.host.name/busybox:1.27.2@sha256:da39a3ee5e6b4b0d3255bfef95601890afd80709"              , "my.host.name", ""     , "busybox"        , "1.27.2", "sha256:da39a3ee5e6b4b0d3255bfef95601890afd80709"},
	{"my.host.name:12345/library/busybox:1.27.2@sha256:da39a3ee5e6b4b0d3255bfef95601890afd80709", "my.host.name", "12345", "library/busybox", "1.27.2", "sha256:da39a3ee5e6b4b0d3255bfef95601890afd80709"},
	{"localhost:12345/library/busybox:1.27.2@sha256:da39a3ee5e6b4b0d3255bfef95601890afd80709"   , "localhost"   , "12345", "library/busybox", "1.27.2", "sha256:da39a3ee5e6b4b0d3255bfef95601890afd80709"}
};

static list<vector<string>> without_splitting_testcases = {
//       input                                                                           repo                            tag       digest
	{"busybox"                                                                     , "busybox"                     , ""      , ""                                               },
	{"local.host:5000/sysdig/agent"                                                , "local.host:5000/sysdig/agent", ""      , ""                                               },
	{"sysdig/agent:dev"                                                            , "sysdig/agent"                , "dev"   , ""                                               },
	{"local.host:5000/sysdig:1.0"                                                  , "local.host:5000/sysdig"      , "1.0"   , ""                                               },
	{"sysdig@sha256:da39a3ee5e6b4b0d3255bfef95601890afd80709"                      , "sysdig"                      , ""      , "sha256:da39a3ee5e6b4b0d3255bfef95601890afd80709"},
	{"local.host:5000/nginx@sha256:da39a3ee5e6b4b0d3255bfef95601890afd80709"       , "local.host:5000/nginx"       , ""      , "sha256:da39a3ee5e6b4b0d3255bfef95601890afd80709"},
	{"sysdig:1.0@sha256:da39a3ee5e6b4b0d3255bfef95601890afd80709"                  , "sysdig"                      , "1.0"   , "sha256:da39a3ee5e6b4b0d3255bfef95601890afd80709"},
	{"local.host:5000/nginx:alpine@sha256:da39a3ee5e6b4b0d3255bfef95601890afd80709", "local.host:5000/nginx"       , "alpine", "sha256:da39a3ee5e6b4b0d3255bfef95601890afd80709"}
};

#define CHECK_VALUE(name, actual, expected) ASSERT_EQ(actual, expected) << "Expected " << name " '" << expected << "' did not match actual value '" << actual << "'"

TEST(container_image_splitting_test, with_repo_splitting)
{
	for(auto &testcase : with_splitting_testcases)
	{
		string hostname;
		string port;
		string name;
		string tag;
		string digest;

		sinsp_utils::split_container_image(testcase[0],
						   hostname, port,
						   name,
						   tag, digest);

		CHECK_VALUE("hostname", hostname, testcase[1]);
		CHECK_VALUE("port", port, testcase[2]);
		CHECK_VALUE("name", name, testcase[3]);
		CHECK_VALUE("tag", tag, testcase[4]);
		CHECK_VALUE("digest", digest, testcase[5]);
	}
}

TEST(container_image_splitting_test, without_repo_splitting)
{
	for(auto &testcase : without_splitting_testcases)
	{
		string hostname, port;
		string repo;
		string tag;
		string digest;

		sinsp_utils::split_container_image(testcase[0],
						   hostname, port,
						   repo,
						   tag, digest,
						   false);

		CHECK_VALUE("repo", repo, testcase[1]);
		CHECK_VALUE("tag", tag, testcase[2]);
		CHECK_VALUE("digest", digest, testcase[3]);
	}
}
