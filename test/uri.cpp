#include <gtest.h>
#include "sinsp.h"
#include "uri.h"

using namespace std;

TEST(uri, parse)
{
	uri u("http://123.45.67.89:54321/my/path/to/file.ext?query=xyz&me=123");
	EXPECT_EQ("http", u.get_scheme());
	EXPECT_FALSE(u.is_secure());
	EXPECT_TRUE(u.get_user().empty());
	EXPECT_TRUE(u.get_password().empty());
	EXPECT_EQ("123.45.67.89", u.get_host());
	EXPECT_EQ(54321, u.get_port());
	EXPECT_EQ("/my/path/to/file.ext", u.get_path());
	EXPECT_EQ("query=xyz&me=123", u.get_query());

	uri unp("http://123.45.67.89/my/path/to/file.ext?query=xyz&me=123");
	EXPECT_EQ("http", unp.get_scheme());
	EXPECT_FALSE(unp.is_secure());
	EXPECT_TRUE(unp.get_user().empty());
	EXPECT_TRUE(unp.get_password().empty());
	EXPECT_EQ("123.45.67.89", unp.get_host());
	EXPECT_EQ(80, unp.get_port());
	EXPECT_EQ("/my/path/to/file.ext", unp.get_path());
	EXPECT_EQ("query=xyz&me=123", unp.get_query());
	EXPECT_EQ("http://123.45.67.89/my/path/to/file.ext?query=xyz&me=123", unp.to_string());

	uri unps("https://123.45.67.89/my/path/to/file.ext?query=xyz&me=123");
	EXPECT_EQ("https", unps.get_scheme());
	EXPECT_TRUE(unps.is_secure());
	EXPECT_TRUE(unps.get_user().empty());
	EXPECT_TRUE(unps.get_password().empty());
	EXPECT_EQ("123.45.67.89", unps.get_host());
	EXPECT_EQ(443, unps.get_port());
	EXPECT_EQ("/my/path/to/file.ext", unps.get_path());
	EXPECT_EQ("query=xyz&me=123", unps.get_query());
	EXPECT_EQ("https://123.45.67.89/my/path/to/file.ext?query=xyz&me=123", unps.to_string());

	uri us("https://123.45.67.89:54321/my/path/to/file.ext?query=xyz&me=123");
	EXPECT_EQ("https", us.get_scheme());
	EXPECT_TRUE(us.is_secure());
	EXPECT_TRUE(us.get_user().empty());
	EXPECT_TRUE(us.get_password().empty());
	EXPECT_EQ("123.45.67.89", us.get_host());
	EXPECT_EQ(54321, us.get_port());
	EXPECT_EQ("/my/path/to/file.ext", us.get_path());
	EXPECT_EQ("query=xyz&me=123", us.get_query());
	EXPECT_EQ("https://123.45.67.89:54321/my/path/to/file.ext?query=xyz&me=123", us.to_string());

	uri usc("https://username:password@123.45.67.89:54321/my/path/to/file.ext?query=xyz&me=123");
	EXPECT_EQ("https", usc.get_scheme());
	EXPECT_TRUE(usc.is_secure());
	EXPECT_EQ(usc.get_user(), "username");
	EXPECT_EQ(usc.get_password(), "password");
	EXPECT_EQ("username:password", usc.get_credentials());
	EXPECT_EQ("123.45.67.89", usc.get_host());
	EXPECT_EQ(54321, usc.get_port());
	EXPECT_EQ("/my/path/to/file.ext", usc.get_path());
	EXPECT_EQ("query=xyz&me=123", usc.get_query());
	EXPECT_EQ("https://username:password@123.45.67.89:54321/my/path/to/file.ext?query=xyz&me=123", usc.to_string());
	EXPECT_EQ("https://***:***@123.45.67.89:54321/my/path/to/file.ext?query=xyz&me=123", usc.to_string(false));

	uri uss("https://k8s_admin:!12%34abcd$efg4@123.45.67.89:54321/my/path/to/file.ext?query=xyz&me=123");
	EXPECT_EQ("https", uss.get_scheme());
	EXPECT_TRUE(uss.is_secure());
	EXPECT_EQ(uss.get_user(), "k8s_admin");
	EXPECT_EQ(uss.get_password(), "!12%34abcd$efg4");
	EXPECT_EQ("k8s_admin:!12%34abcd$efg4", uss.get_credentials());
	EXPECT_EQ("123.45.67.89", uss.get_host());
	EXPECT_EQ(54321, uss.get_port());
	EXPECT_EQ("/my/path/to/file.ext", uss.get_path());
	EXPECT_EQ("query=xyz&me=123", uss.get_query());
	EXPECT_EQ("https://k8s_admin:!12%34abcd$efg4@123.45.67.89:54321/my/path/to/file.ext?query=xyz&me=123", uss.to_string());
	EXPECT_EQ("https://***:***@123.45.67.89:54321/my/path/to/file.ext?query=xyz&me=123", uss.to_string(false));

	uri usa("HTTPS://k8s_admin:!12%34ab%40cd$e%3Afg4@123.45.67.89:54321/my/path/to/@file.ext?query=xyz&me=123");
	EXPECT_EQ("https", usa.get_scheme());
	EXPECT_TRUE(usa.is_secure());
	EXPECT_EQ(usa.get_user(), "k8s_admin");
	EXPECT_EQ(usa.get_password(), "!12%34ab%40cd$e%3Afg4");
	EXPECT_EQ("k8s_admin:!12%34ab%40cd$e%3Afg4", usa.get_credentials());
	EXPECT_EQ("123.45.67.89", usa.get_host());
	EXPECT_EQ(54321, usa.get_port());
	EXPECT_EQ("/my/path/to/@file.ext", usa.get_path());
	EXPECT_EQ("query=xyz&me=123", usa.get_query());
	EXPECT_EQ("https://k8s_admin:!12%34ab%40cd$e%3Afg4@123.45.67.89:54321/my/path/to/@file.ext?query=xyz&me=123", usa.to_string());
	EXPECT_EQ("https://***:***@123.45.67.89:54321/my/path/to/@file.ext?query=xyz&me=123", usa.to_string(false));

	try
	{
		uri u("a bad uri");
		ASSERT_TRUE(false);
	}
	catch(sinsp_exception&) {}
	try
	{
		uri u("https://k8s_admin:!12@45@123.45.67.89:54321/my/path/to/@file.ext?query=xyz&me=123");
		ASSERT_TRUE(false);
	}
	catch(sinsp_exception&) {}
	try
	{
		uri u("https://k8s_admin@123.45.67.89:54321/my/path/to/@file.ext?query=xyz&me=123");
		ASSERT_TRUE(false);
	}
	catch(sinsp_exception&) {}

	uri f("  file:///var/run/docker.sock  ");
	EXPECT_EQ("file", f.get_scheme());
	EXPECT_FALSE(f.is_secure());
	EXPECT_EQ(f.get_user(), "");
	EXPECT_EQ(f.get_password(), "");
	EXPECT_EQ("", f.get_credentials());
	EXPECT_EQ("", f.get_host());
	EXPECT_EQ(0, f.get_port());
	EXPECT_EQ("/var/run/docker.sock", f.get_path());
	EXPECT_EQ("", f.get_query());
	EXPECT_EQ("file:///var/run/docker.sock", f.to_string());
	EXPECT_EQ("file:///var/run/docker.sock", f.to_string(false));
	EXPECT_TRUE(f.is_local());

	uri l("http://localhost:8080");
	EXPECT_TRUE(l.is_local());

	uri ll("http://127.0.0.1:8080");
	EXPECT_TRUE(ll.is_local());
}

TEST(uri, encode)
{
	EXPECT_EQ(uri::encode(uri::SPECIAL_CHARS), "%21%23%24%26%27%28%29%2A%2B%2C%2F%3A%3B%3D%3F%40%5B%5D");
	EXPECT_EQ(uri::decode("%21%23%24%26%27%28%29%2A%2B%2C%2F%3a%3B%3d%3F%40%5b%5D"), uri::SPECIAL_CHARS);
	EXPECT_EQ(uri::encode(uri::AMBIGUOUS_CHARS), "%20%22%25%2D%2E%3C%3E%5C%5E%5F%60%7B%7C%7D%7E");
	EXPECT_EQ(uri::decode("%20%22%25%2d%2E%3c%3e%5C%5E%5f%60%7b%7C%7d%7E"), uri::AMBIGUOUS_CHARS);
	EXPECT_EQ(uri::decode("https://k8s_admin:!12%34ab%40cd$e%3Afg4@123.45.67.89:54321/my/path/to/@file.ext?query=xy%20z&me=123"),
						  "https://k8s_admin:!124ab@cd$e:fg4@123.45.67.89:54321/my/path/to/@file.ext?query=xy z&me=123");
	EXPECT_EQ(uri::encode("!124ab@cd$e:fg4"), "%21124ab%40cd%24e%3Afg4");
}
