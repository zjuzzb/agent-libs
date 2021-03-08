/**
 * @file
 *
 * Unit tests for scope_resolver_iface
 *
 * @copyright Copyright (c) 2021 Sysdig Inc., All Rights Reserved
 */

#include <gtest.h>

#include "scope_resolver_iface.h"

using namespace std;

class scope_resolver_iface_test : public testing::Test
{
protected:
	virtual void SetUp()
	{
		env_prod_eq.set_key("agent.tag.environment");
		env_prod_eq.add_values()->assign("production");
		env_prod_eq.set_op(draiosproto::EQ);

		env_prod_not_eq = env_prod_eq;
		env_prod_not_eq.set_op(draiosproto::NOT_EQ);

		env_prod_contains.set_key("agent.tag.environment");
		env_prod_contains.add_values()->assign("uction");
		env_prod_contains.set_op(draiosproto::CONTAINS);

		env_prod_not_contains = env_prod_contains;
		env_prod_not_contains.set_op(draiosproto::NOT_CONTAINS);

		env_prod_startswith.set_key("agent.tag.environment");
		env_prod_startswith.add_values()->assign("prod");
		env_prod_startswith.set_op(draiosproto::STARTS_WITH);

		env_prod_in.set_key("agent.tag.environment");
		env_prod_in.add_values()->assign("production");
		env_prod_in.add_values()->assign("test");
		env_prod_in.set_op(draiosproto::IN_SET);

		env_prod_not_in = env_prod_in;
		env_prod_not_in.set_op(draiosproto::NOT_IN_SET);

		dept_apps_eq.set_key("agent.tag.department");
		dept_apps_eq.add_values()->assign("apps");
		dept_apps_eq.set_op(draiosproto::EQ);

		container_nginx_eq.set_key("container.image.repo");
		container_nginx_eq.add_values()->assign("nginx");
		container_nginx_eq.set_op(draiosproto::EQ);

		env_prod_preds.Add()->CopyFrom(env_prod_eq);

		env_prod_dept_apps_preds.Add()->CopyFrom(env_prod_eq);
		env_prod_dept_apps_preds.Add()->CopyFrom(dept_apps_eq);

		env_prod_dept_apps_container_nginx_preds.Add()->CopyFrom(env_prod_eq);
		env_prod_dept_apps_container_nginx_preds.Add()->CopyFrom(dept_apps_eq);
		env_prod_dept_apps_container_nginx_preds.Add()->CopyFrom(container_nginx_eq);

		env_prod_container_nginx_preds.Add()->CopyFrom(env_prod_eq);
		env_prod_container_nginx_preds.Add()->CopyFrom(container_nginx_eq);

		container_nginx_preds.Add()->CopyFrom(container_nginx_eq);

		env_prod = {{"agent.tag.environment", "production"}};
		env_dev = {{"agent.tag.environment", "dev"}};
		env_dev_dept_ops = {{"agent.tag.environment", "dev"}, {"agent.tag.department", "ops"}};
		env_dev_dept_apps = {{"agent.tag.environment", "dev"}, {"agent.tag.department", "apps"}};
		env_prod_dept_apps = {{"agent.tag.environment", "production"}, {"agent.tag.department", "apps"}};
	}

	draiosproto::scope_predicate env_prod_eq;
	draiosproto::scope_predicate env_prod_not_eq;
	draiosproto::scope_predicate env_prod_contains;
	draiosproto::scope_predicate env_prod_not_contains;
	draiosproto::scope_predicate env_prod_startswith;
	draiosproto::scope_predicate env_prod_in;
	draiosproto::scope_predicate env_prod_not_in;
	draiosproto::scope_predicate dept_apps_eq;
	draiosproto::scope_predicate container_nginx_eq;

	scope_predicates empty_preds;
	scope_predicates env_prod_preds;
	scope_predicates env_prod_dept_apps_preds;
	scope_predicates env_prod_container_nginx_preds;
	scope_predicates env_prod_dept_apps_container_nginx_preds;
	scope_predicates container_nginx_preds;

	scope_resolver_iface::tags_map empty_tags;
	scope_resolver_iface::tags_map env_prod;
	scope_resolver_iface::tags_map env_dev;
	scope_resolver_iface::tags_map env_dev_dept_ops;
	scope_resolver_iface::tags_map env_dev_dept_apps;
	scope_resolver_iface::tags_map env_prod_dept_apps;
};

TEST_F(scope_resolver_iface_test, eq_true)
{
	ASSERT_TRUE(scope_resolver_iface::match_predicate(env_prod_eq, string("production")));
}

TEST_F(scope_resolver_iface_test, eq_false)
{
	ASSERT_FALSE(scope_resolver_iface::match_predicate(env_prod_eq, string("dev")));
}

TEST_F(scope_resolver_iface_test, not_eq_true)
{
	ASSERT_TRUE(scope_resolver_iface::match_predicate(env_prod_not_eq, string("dev")));
}

TEST_F(scope_resolver_iface_test, not_eq_false)
{
	ASSERT_FALSE(scope_resolver_iface::match_predicate(env_prod_not_eq, string("production")));
}

TEST_F(scope_resolver_iface_test, contains_true)
{
	ASSERT_TRUE(scope_resolver_iface::match_predicate(env_prod_contains, string("production")));
}

TEST_F(scope_resolver_iface_test, contains_false)
{
	ASSERT_FALSE(scope_resolver_iface::match_predicate(env_prod_contains, string("dev")));
}

TEST_F(scope_resolver_iface_test, not_contains_true)
{
	ASSERT_TRUE(scope_resolver_iface::match_predicate(env_prod_not_contains, string("dev")));
}

TEST_F(scope_resolver_iface_test, not_contains_false)
{
	ASSERT_FALSE(scope_resolver_iface::match_predicate(env_prod_not_contains, string("production")));
}

TEST_F(scope_resolver_iface_test, startswith_true)
{
	ASSERT_TRUE(scope_resolver_iface::match_predicate(env_prod_startswith, string("production")));
}

TEST_F(scope_resolver_iface_test, startswith_false)
{
	ASSERT_FALSE(scope_resolver_iface::match_predicate(env_prod_startswith, string("dev")));
}

TEST_F(scope_resolver_iface_test, in_true)
{
	ASSERT_TRUE(scope_resolver_iface::match_predicate(env_prod_in, string("production")));
}

TEST_F(scope_resolver_iface_test, in_false)
{
	ASSERT_FALSE(scope_resolver_iface::match_predicate(env_prod_in, string("dev")));
}

TEST_F(scope_resolver_iface_test, not_in_true)
{
	ASSERT_TRUE(scope_resolver_iface::match_predicate(env_prod_not_in, string("dev")));
}

TEST_F(scope_resolver_iface_test, not_in_false)
{
	ASSERT_FALSE(scope_resolver_iface::match_predicate(env_prod_not_in, string("test")));
}

TEST_F(scope_resolver_iface_test, preds_none_tags_none)
{
	scope_predicates remaining_preds;

	ASSERT_TRUE(scope_resolver_iface::match_agent_tag_predicates(empty_preds, empty_tags, remaining_preds));
	ASSERT_TRUE(remaining_preds == empty_preds);
}

TEST_F(scope_resolver_iface_test, preds_none_one_tag)
{
	scope_predicates remaining_preds;

	ASSERT_TRUE(scope_resolver_iface::match_agent_tag_predicates(empty_preds, env_prod, remaining_preds));
	ASSERT_TRUE(remaining_preds == empty_preds);
}

TEST_F(scope_resolver_iface_test, preds_one_one_tag)
{
	scope_predicates remaining_preds;

	ASSERT_TRUE(scope_resolver_iface::match_agent_tag_predicates(env_prod_preds, env_prod, remaining_preds));
	ASSERT_TRUE(remaining_preds == empty_preds);
}

TEST_F(scope_resolver_iface_test, preds_one_one_tag_disjoint)
{
	scope_predicates remaining_preds;

	ASSERT_FALSE(scope_resolver_iface::match_agent_tag_predicates(env_prod_preds, env_dev, remaining_preds));
}

TEST_F(scope_resolver_iface_test, preds_one_one_tag_remainder)
{
	scope_predicates remaining_preds;

	ASSERT_TRUE(scope_resolver_iface::match_agent_tag_predicates(container_nginx_preds, env_prod, remaining_preds));
	ASSERT_TRUE(remaining_preds == container_nginx_preds);
}

TEST_F(scope_resolver_iface_test, preds_two_one_tag)
{
	scope_predicates remaining_preds;

	ASSERT_FALSE(scope_resolver_iface::match_agent_tag_predicates(env_prod_dept_apps_preds, env_prod, remaining_preds));
}

TEST_F(scope_resolver_iface_test, preds_two_one_tag_remainder)
{
	scope_predicates remaining_preds;

	ASSERT_TRUE(scope_resolver_iface::match_agent_tag_predicates(env_prod_container_nginx_preds, env_prod, remaining_preds));
	ASSERT_TRUE(remaining_preds == container_nginx_preds);
}

TEST_F(scope_resolver_iface_test, preds_two_one_tag_disjoint)
{
	scope_predicates remaining_preds;

	ASSERT_FALSE(scope_resolver_iface::match_agent_tag_predicates(env_prod_container_nginx_preds, env_dev, remaining_preds));
}

TEST_F(scope_resolver_iface_test, preds_two_two_tags)
{
	scope_predicates remaining_preds;

	ASSERT_TRUE(scope_resolver_iface::match_agent_tag_predicates(env_prod_dept_apps_preds, env_prod_dept_apps, remaining_preds));
	ASSERT_TRUE(remaining_preds == empty_preds);
}

TEST_F(scope_resolver_iface_test, preds_two_two_tags_disjoint)
{
	scope_predicates remaining_preds;

	ASSERT_FALSE(scope_resolver_iface::match_agent_tag_predicates(env_prod_dept_apps_preds, env_dev_dept_ops, remaining_preds));
}

TEST_F(scope_resolver_iface_test, preds_two_two_tags_partial)
{
	scope_predicates remaining_preds;

	ASSERT_FALSE(scope_resolver_iface::match_agent_tag_predicates(env_prod_dept_apps_preds, env_dev_dept_apps, remaining_preds));
}

TEST_F(scope_resolver_iface_test, preds_three_two_tags_remainder)
{
	scope_predicates remaining_preds;

	ASSERT_TRUE(scope_resolver_iface::match_agent_tag_predicates(env_prod_dept_apps_container_nginx_preds, env_prod_dept_apps, remaining_preds));
	ASSERT_TRUE(remaining_preds == container_nginx_preds);
}

