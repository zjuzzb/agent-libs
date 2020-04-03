#include "common_logger.h"
#include "draios.pb.h"
#include "feature_manager.h"
#include "scoped_config.h"

#include <gtest.h>

TEST(feature_manager, base_dependencies)
{
	feature_manager fm;
	feature_base empty_dep((feature_name)1,
	                       &draiosproto::feature_status::set_prometheus_enabled,
	                       {},
	                       fm);
	feature_base some_dep((feature_name)2,
	                      &draiosproto::feature_status::set_prometheus_enabled,
	                      {(feature_name)1},
	                      fm);

	EXPECT_EQ(empty_dep.get_dependencies().size(), 0);
	EXPECT_EQ(some_dep.get_dependencies().size(), 1);
	EXPECT_EQ(some_dep.get_dependencies().front(), 1);

	empty_dep.set_enabled(false);
	EXPECT_FALSE(empty_dep.get_enabled());
	empty_dep.set_enabled(true);
	EXPECT_TRUE(empty_dep.get_enabled());
}

TEST(feature_manager, base_verify_dependencies)
{
	feature_manager fm;
	feature_base empty_dep((feature_name)1,
	                       &draiosproto::feature_status::set_prometheus_enabled,
	                       {},
	                       fm);
	EXPECT_TRUE(empty_dep.verify_dependencies());

	feature_base some_dep((feature_name)2,
	                      &draiosproto::feature_status::set_prometheus_enabled,
	                      {(feature_name)1},
	                      fm);
	empty_dep.set_enabled(false);
	EXPECT_FALSE(some_dep.verify_dependencies());

	empty_dep.set_enabled(true);
	EXPECT_TRUE(some_dep.verify_dependencies());
}

TEST(feature_manager, basic)
{
	feature_manager fm;

	// Why do we have 11 of these things? Feature manager needs an implementation of each
	// feature before it will let you inititialize. There are 11 features. I have
	// to provide some CB function in the feature constructor, so i just stuff
	// prometheus_enabled in since I don't really care. it's a dummy.
	feature_base fb0((feature_name)0, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb1((feature_name)1, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb2((feature_name)2, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb3((feature_name)3, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb4((feature_name)4, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb5((feature_name)5, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb6((feature_name)6, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb7((feature_name)7, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb8((feature_name)8, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb9((feature_name)9, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb10((feature_name)10,
	                  &draiosproto::feature_status::set_prometheus_enabled,
	                  {},
	                  fm);
	feature_base fb11((feature_name)11,
	                  &draiosproto::feature_status::set_prometheus_enabled,
	                  {},
	                  fm);

	fm.initialize();

	fb0.set_enabled(false);
	EXPECT_FALSE(fm.get_enabled((feature_name)0));
	fb0.set_enabled(true);
	EXPECT_TRUE(fm.get_enabled((feature_name)0));
}

class init_test : public feature_base
{
public:
	init_test(feature_manager& fm)
	    : feature_base((feature_name)0,
	                   &draiosproto::feature_status::set_commandline_capture_enabled,
	                   {},
	                   fm),
	      m_init_called(false)
	{
	}
	bool initialize() override
	{
		m_init_called = true;
		return true;
	}

	bool m_init_called;
};

TEST(feature_manager, base_initialize_called)
{
	feature_manager fm;
	init_test fb(fm);
	feature_base fb1((feature_name)1, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb2((feature_name)2, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb3((feature_name)3, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb4((feature_name)4, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb5((feature_name)5, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb6((feature_name)6, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb7((feature_name)7, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb8((feature_name)8, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb9((feature_name)9, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb10((feature_name)10,
	                  &draiosproto::feature_status::set_prometheus_enabled,
	                  {},
	                  fm);
	feature_base fb11((feature_name)11,
	                  &draiosproto::feature_status::set_prometheus_enabled,
	                  {},
	                  fm);

	test_helpers::scoped_config<bool> memdump("prometheus.enabled", true);
	ASSERT_FALSE(fb.m_init_called);
	fm.initialize();
	ASSERT_TRUE(fb.m_init_called);
}

TEST(feature_manager, base_disable)
{
	feature_manager fm;
	feature_base empty_dep((feature_name)1,
	                       &draiosproto::feature_status::set_prometheus_enabled,
	                       {},
	                       fm);
	EXPECT_TRUE(empty_dep.verify_dependencies());

	feature_base some_dep((feature_name)2,
	                      &draiosproto::feature_status::set_prometheus_enabled,
	                      {(feature_name)1},
	                      fm);
	empty_dep.set_enabled(true);
	some_dep.set_enabled(false);

	EXPECT_TRUE(fm.disable((feature_name)1));
	EXPECT_FALSE(fm.get_enabled((feature_name)1));

	empty_dep.set_enabled(true);
	some_dep.set_enabled(true);

	EXPECT_FALSE(fm.disable((feature_name)1));
	EXPECT_TRUE(fm.get_enabled((feature_name)1));
}

TEST(feature_manager, invalid_mode)
{
	feature_manager fm;
	feature_base fb0((feature_name)0, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb1((feature_name)1, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb2((feature_name)2, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb3((feature_name)3, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb4((feature_name)4, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb5((feature_name)5, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb6((feature_name)6, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb7((feature_name)7, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb8((feature_name)8, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb9((feature_name)9, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb10((feature_name)10,
	                  &draiosproto::feature_status::set_prometheus_enabled,
	                  {},
	                  fm);
	feature_base fb11((feature_name)11,
	                  &draiosproto::feature_status::set_prometheus_enabled,
	                  {},
	                  fm);

	{
		test_helpers::scoped_config<bool> pom("prometheus.enabled", true);
		test_helpers::scoped_config<bool> sd("statsd.enabled", false);
		fm.initialize();

		EXPECT_TRUE(fm.get_enabled(PROMETHEUS));
		EXPECT_FALSE(fm.get_enabled(STATSD));
	}
	{
		test_helpers::scoped_config<bool> pom("prometheus.enabled", false);
		test_helpers::scoped_config<bool> sd("statsd.enabled", true);
		fm.initialize();

		EXPECT_FALSE(fm.get_enabled(PROMETHEUS));
		EXPECT_TRUE(fm.get_enabled(STATSD));
	}
}

TEST(feature_manager, monitor_mode)
{
	feature_manager fm;
	feature_base fb0((feature_name)0, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb1((feature_name)1, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb2((feature_name)2, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb3((feature_name)3, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb4((feature_name)4, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb5((feature_name)5, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb6((feature_name)6, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb7((feature_name)7, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb8((feature_name)8, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb9((feature_name)9, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb10((feature_name)10,
	                  &draiosproto::feature_status::set_prometheus_enabled,
	                  {},
	                  fm);
	feature_base fb11((feature_name)11,
	                  &draiosproto::feature_status::set_prometheus_enabled,
	                  {},
	                  fm);

	{
		test_helpers::scoped_config<bool> pom("prometheus.enabled", true);
		test_helpers::scoped_config<bool> sd("statsd.enabled", false);
		test_helpers::scoped_config<std::string> mode("feature.mode", "monitor");
		fm.initialize();

		EXPECT_FALSE(fm.get_enabled(PROMETHEUS));
		EXPECT_TRUE(fm.get_enabled(STATSD));
	}
	{
		test_helpers::scoped_config<bool> pom("prometheus.enabled", false);
		test_helpers::scoped_config<bool> sd("statsd.enabled", true);
		test_helpers::scoped_config<std::string> mode("feature.mode", "monitor");
		fm.initialize();

		EXPECT_FALSE(fm.get_enabled(PROMETHEUS));
		EXPECT_TRUE(fm.get_enabled(STATSD));
	}
}

TEST(feature_manager, monitor_light_mode)
{
	feature_manager fm;
	feature_base fb0((feature_name)0, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb1((feature_name)1, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb2((feature_name)2, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb3((feature_name)3, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb4((feature_name)4, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb5((feature_name)5, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb6((feature_name)6, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb7((feature_name)7, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb8((feature_name)8, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb9((feature_name)9, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb10((feature_name)10,
	                  &draiosproto::feature_status::set_prometheus_enabled,
	                  {},
	                  fm);
	feature_base fb11((feature_name)11,
	                  &draiosproto::feature_status::set_prometheus_enabled,
	                  {},
	                  fm);

	{
		test_helpers::scoped_config<bool> pom("prometheus.enabled", true);
		test_helpers::scoped_config<bool> sd("statsd.enabled", false);
		test_helpers::scoped_config<std::string> mode("feature.mode", "monitor_light");
		fm.initialize();

		EXPECT_FALSE(fm.get_enabled(PROMETHEUS));
		EXPECT_FALSE(fm.get_enabled(STATSD));
	}
	{
		test_helpers::scoped_config<bool> pom("prometheus.enabled", false);
		test_helpers::scoped_config<bool> sd("statsd.enabled", true);
		test_helpers::scoped_config<std::string> mode("feature.mode", "monitor_light");
		fm.initialize();

		EXPECT_FALSE(fm.get_enabled(PROMETHEUS));
		EXPECT_FALSE(fm.get_enabled(STATSD));
	}
}

TEST(feature_manager, base_emit_protobuf)
{
	feature_manager fm;
	feature_base fb0((feature_name)0, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);

	draiosproto::feature_status proto;
	fb0.set_enabled(false);
	fb0.emit_enabled(proto);
	EXPECT_FALSE(proto.prometheus_enabled());
	fb0.set_enabled(true);
	fb0.emit_enabled(proto);
	EXPECT_TRUE(proto.prometheus_enabled());
}

TEST(feature_manager, to_protobuf)
{
	feature_manager fm;
	feature_base fb0((feature_name)0, &draiosproto::feature_status::set_prometheus_enabled, {}, fm);
	feature_base fb1((feature_name)1, &draiosproto::feature_status::set_statsd_enabled, {}, fm);
	feature_base fb2((feature_name)2, &draiosproto::feature_status::set_jmx_enabled, {}, fm);
	feature_base fb3((feature_name)3, &draiosproto::feature_status::set_app_checks_enabled, {}, fm);
	feature_base fb4((feature_name)4, &draiosproto::feature_status::set_cointerface_enabled, {}, fm);
	feature_base fb5((feature_name)5, &draiosproto::feature_status::set_driver_enabled, {}, fm);
	feature_base fb6((feature_name)6, &draiosproto::feature_status::set_secure_enabled, {}, fm);
	feature_base fb7((feature_name)7, &draiosproto::feature_status::set_commandline_capture_enabled, {}, fm);
	feature_base fb8((feature_name)8, &draiosproto::feature_status::set_baseliner_enabled, {}, fm);
	feature_base fb9((feature_name)9, &draiosproto::feature_status::set_memdump_enabled, {}, fm);
	feature_base fb10((feature_name)10,
	                  &draiosproto::feature_status::set_secure_audit_enabled,
	                  {},
	                  fm);
	feature_base fb11((feature_name)11,
	                  &draiosproto::feature_status::set_full_syscalls_enabled,
	                  {},
	                  fm);

	{
		test_helpers::scoped_config<std::string> mode("feature.mode", "monitor_light");
		fm.initialize();
		draiosproto::feature_status proto;
		fm.to_protobuf(proto);
		EXPECT_EQ(proto.mode(), draiosproto::agent_mode::light);
		EXPECT_FALSE(proto.prometheus_enabled());
		EXPECT_FALSE(proto.statsd_enabled());
		EXPECT_FALSE(proto.jmx_enabled());
		EXPECT_FALSE(proto.app_checks_enabled());
		EXPECT_FALSE(proto.cointerface_enabled());
		EXPECT_FALSE(proto.driver_enabled());
		EXPECT_FALSE(proto.secure_enabled());
		EXPECT_FALSE(proto.commandline_capture_enabled());
		EXPECT_FALSE(proto.baseliner_enabled());
		EXPECT_FALSE(proto.memdump_enabled());
		EXPECT_FALSE(proto.secure_audit_enabled());
		EXPECT_FALSE(proto.full_syscalls_enabled());
	}
	{
		test_helpers::scoped_config<std::string> mode("feature.mode", "none");
		fm.initialize();
		draiosproto::feature_status proto;
		fm.to_protobuf(proto);
		EXPECT_EQ(proto.mode(), draiosproto::agent_mode::legacy);
	}
	{
		test_helpers::scoped_config<std::string> mode("feature.mode", "monitor");
		fm.initialize();
		draiosproto::feature_status proto;
		fm.to_protobuf(proto);
		EXPECT_EQ(proto.mode(), draiosproto::agent_mode::normal);
		EXPECT_FALSE(proto.prometheus_enabled());
		EXPECT_TRUE(proto.statsd_enabled());
		EXPECT_TRUE(proto.jmx_enabled());
		EXPECT_TRUE(proto.app_checks_enabled());
		EXPECT_TRUE(proto.cointerface_enabled());
		EXPECT_TRUE(proto.driver_enabled());
		EXPECT_FALSE(proto.secure_enabled());
		EXPECT_FALSE(proto.commandline_capture_enabled());
		EXPECT_FALSE(proto.baseliner_enabled());
		EXPECT_FALSE(proto.memdump_enabled());
		EXPECT_FALSE(proto.secure_audit_enabled());
		EXPECT_TRUE(proto.full_syscalls_enabled());
	}
}
