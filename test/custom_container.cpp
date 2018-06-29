#define VISIBILITY_PRIVATE
#include <gtest.h>

#include "custom_container.h"

using namespace std;
using namespace custom_container;

class custom_container_f : public ::testing::Test {
};

TEST_F(custom_container_f, match)
{
	Poco::RegularExpression rx("^foo([0-9]+)bar([0-9a-f]+)$", 0);
	Poco::RegularExpression::MatchVec matches;
	string s = "foo123bar123ff";

	ASSERT_EQ(3, rx.match(s, 0, matches, 0));

	match m = { .m_str = s, .m_matches = matches };

	string out;

	m.render(out, 0);
	EXPECT_EQ(s, out);
	out.clear();

	m.render(out, 1);
	EXPECT_EQ("123", out);
	out.clear();

	m.render(out, 2);
	EXPECT_EQ("123ff", out);
	out.clear();

	bool thrown = false;
	try {
		m.render(out, 3);
	} catch (Poco::RuntimeException e) {
		thrown = true;
	}
	ASSERT_TRUE(thrown);
}

TEST_F(custom_container_f, subst_token)
{
	Poco::RegularExpression rx("^foo([0-9]+)bar([0-9a-f]+)$", 0);
	Poco::RegularExpression::MatchVec matches;
	render_context ctx;
	string s = "foo123bar123ff";
	vector<string> env = {
		"VAR1=var1",
		"VAR2=var2"
	};

	ASSERT_EQ(3, rx.match(s, 0, matches, 0));

	ctx.emplace("foo", move(match { .m_str = s, .m_matches = matches }));

	{
		string out;
		subst_token st1("foo", -1);
		st1.render(out, ctx, env);
		EXPECT_EQ("foo", out);
	}
	{
		string out;
		subst_token st1("foo", 0);
		st1.render(out, ctx, env);
		EXPECT_EQ(s, out);
	}
	{
		string out;
		subst_token st1("foo", 2);
		st1.render(out, ctx, env);
		EXPECT_EQ("123ff", out);
	}
	{
		string out;
		subst_token st1("VAR1", 0);
		st1.render(out, ctx, env);
		EXPECT_EQ("var1", out);
	}
	{
		string out;
		subst_token st1("VAR3", 0);
		st1.render(out, ctx, env);
		EXPECT_EQ("", out);
	}
}

TEST_F(custom_container_f, subst_template)
{
	Poco::RegularExpression rx("^foo([0-9]+)bar([0-9a-f]+)$", 0);
	Poco::RegularExpression::MatchVec matches;
	render_context ctx;
	string s = "foo123bar123ff";
	vector<string> env = {
		"VAR1=var1",
		"VAR2=var2"
	};

	ASSERT_EQ(3, rx.match(s, 0, matches, 0));

	ctx.emplace("foo", move(match { .m_str = s, .m_matches = matches }));

	{
		subst_template st1;
		EXPECT_TRUE(st1.empty());
	}
	{
		subst_template st1("abc<foo:2>def<VAR2>");
		const auto& tokens = st1.get_tokens();
		ASSERT_EQ(4u, tokens.size());

		EXPECT_EQ(tokens[0], subst_token("abc", -1));
		EXPECT_EQ(tokens[1], subst_token("foo", 2));
		EXPECT_EQ(tokens[2], subst_token("def", -1));
		EXPECT_EQ(tokens[3], subst_token("VAR2", 0));

		EXPECT_FALSE(st1.empty());

		string out;
		st1.render(out, ctx, env);
		EXPECT_EQ("abc123ffdefvar2", out);
	}
}
