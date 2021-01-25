#include "container_manager.h"
#include "draios.pb.h"

#include <gtest.h>

using namespace agentone;

TEST(container, basic)
{
	container test_container("id", "name", "image", {{"some_key", "some_value"}});
	EXPECT_EQ(test_container.get_id(), "id");
	EXPECT_EQ(test_container.get_name(), "name");
	EXPECT_EQ(test_container.get_image(), "image");
	EXPECT_EQ(test_container.get_labels().find("some_key")->second, "some_value");
}

TEST(container, refs)
{
	container test_container("id", "name", "image", {{"some_key", "some_value"}});
	EXPECT_EQ(test_container.get_ref(), 0);
	test_container.ref();
	EXPECT_EQ(test_container.get_ref(), 1);
	test_container.deref();
	EXPECT_EQ(test_container.get_ref(), 0);
}


TEST(container_manager, basic)
{
	container_manager cm;
	EXPECT_EQ(cm.get_container_list().size(), 0);
	EXPECT_EQ(cm.get_container("some id"), nullptr);
}

TEST(container_manager, build_new)
{
	container_manager cm;
	cm.build_container("id", "name", "image", {{"some_key", "some_value"}});
	auto c =  cm.get_container("id");
	ASSERT_NE(c, nullptr);
	EXPECT_EQ(c->get_id(), "id");
	EXPECT_EQ(c->get_name(), "name");
	EXPECT_EQ(c->get_image(), "image");
	EXPECT_EQ(c->get_labels().find("some_key")->second, "some_value");
	EXPECT_EQ(c->get_ref(), 1);
	auto list = cm.get_container_list();
	ASSERT_EQ(list.size(), 1);
	auto c_from_list = list.find("id");
	ASSERT_NE(c_from_list, list.end());
	EXPECT_EQ(&*(c_from_list->second), &*c);
}

TEST(container_manager, build_replacement)
{
	container_manager cm;
	cm.build_container("id", "name", "image", {});
	cm.build_container("id", "name2", "image2", {});
	auto c =  cm.get_container("id");
	EXPECT_EQ(c->get_name(), "name");
	EXPECT_EQ(cm.get_container_list().size(), 1);
	// TWO refs since two people tried to create this
	EXPECT_EQ(c->get_ref(), 2);
}

TEST(container_manager, build_multiple)
{
	container_manager cm;
	cm.build_container("id", "name", "image", {});
	cm.build_container("id2", "name2", "image2", {});
	auto c =  cm.get_container("id");
	EXPECT_EQ(c->get_name(), "name");
	EXPECT_EQ(c->get_ref(), 1);
	c =  cm.get_container("id2");
	EXPECT_EQ(c->get_name(), "name2");
	EXPECT_EQ(c->get_ref(), 1);
	EXPECT_EQ(cm.get_container_list().size(), 2);
}

TEST(container_manager, remove)
{
	container_manager cm;
	cm.build_container("id", "name", "image", {});
	cm.build_container("id2", "name2", "image2", {});
	cm.remove_container("id2");
	auto c =  cm.get_container("id");
	EXPECT_EQ(c->get_name(), "name");
	c =  cm.get_container("id2");
	EXPECT_EQ(c, nullptr);
	EXPECT_EQ(cm.get_container_list().size(), 1);

	// Just for fun, we'll create a second instance of ID just to ensure we have
	// to remove it twice
	cm.build_container("id", "name", "image", {});
	EXPECT_EQ(cm.get_container_list().size(), 1);
	c =  cm.get_container("id");
	EXPECT_EQ(c->get_ref(), 2);
	cm.remove_container("id");
	EXPECT_EQ(c->get_ref(), 1);
	cm.remove_container("id");
	EXPECT_EQ(c->get_ref(), 0);
	c =  cm.get_container("id");
	EXPECT_EQ(c, nullptr);
	EXPECT_EQ(cm.get_container_list().size(), 0);
}

TEST(container_manager, remove_not_found)
{
	container_manager cm;
	cm.build_container("id", "name", "image", {});
	cm.build_container("id2", "name2", "image2", {});
	cm.remove_container("unknown id");
	EXPECT_EQ(cm.get_container_list().size(), 2);
}

TEST(protobuf_container_serializer, serialize)
{
	container_manager cm;
	cm.build_container("id", "name", "image", {{"some_key", "some_value"}});
	cm.build_container("id2", "name2", "image2", {{"some_key2", "some_value2"}});

	container_serializer<draiosproto::metrics> cs;
	draiosproto::metrics metrics;
	cs.serialize(cm, metrics);
	ASSERT_EQ(metrics.containers().size(), 2);
	EXPECT_EQ(metrics.containers()[0].id(), "id");
	EXPECT_EQ(metrics.containers()[0].image(), "image");
	EXPECT_EQ(metrics.containers()[0].name(), "name");
	EXPECT_EQ(metrics.containers()[0].labels()[0].key(), "some_key");
	EXPECT_EQ(metrics.containers()[0].labels()[0].value(), "some_value");
	EXPECT_EQ(metrics.containers()[1].id(), "id2");
	EXPECT_EQ(metrics.containers()[1].image(), "image2");
	EXPECT_EQ(metrics.containers()[1].name(), "name2");
	EXPECT_EQ(metrics.containers()[1].labels()[0].key(), "some_key2");
	EXPECT_EQ(metrics.containers()[1].labels()[0].value(), "some_value2");
}
