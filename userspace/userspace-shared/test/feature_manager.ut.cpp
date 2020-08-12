#include "common_logger.h"
#include "draios.pb.h"
#include "feature_manager.h"
#include "scoped_config.h"
#include "scoped_configuration.h"

#include <gtest.h>

using namespace test_helpers;

class test_helper
{
public:
	static bool verify_dependencies(feature_manager& fm) { return fm.verify_dependencies(); }
	static bool enable(feature_manager& fm, feature_name feature, bool force)
	{
		return fm.enable(feature, force);
	}
	static bool disable(feature_manager& fm, feature_name feature, bool force)
	{
		return fm.disable(feature, force);
	}
	static bool try_enable(feature_manager& fm, feature_name feature)
	{
		return fm.try_enable(feature);
	}
	static bool try_disable(feature_manager& fm, feature_name feature)
	{
		return fm.try_disable(feature);
	}
};

namespace
{
// this config normally lives in libsanalyzer, but we're in userspace shared, so we
// have to declare an instance of it
type_config<uint32_t> c_url_table_size(1024, "", "http", "url_table_size");
type_config<bool> c_10s_flush_enable(false, "", "10s_flush_enable");

class dummy_features
{
public:
	dummy_features(feature_manager& fm)
	    : fb0(PROMETHEUS, &draiosproto::feature_status::set_prometheus_enabled, {}, fm),
	      fb1(STATSD, &draiosproto::feature_status::set_statsd_enabled, {}, fm),
	      fb2(JMX, &draiosproto::feature_status::set_jmx_enabled, {}, fm),
	      fb3(APP_CHECKS, &draiosproto::feature_status::set_app_checks_enabled, {}, fm),
	      fb4(COINTERFACE, &draiosproto::feature_status::set_cointerface_enabled, {}, fm),
	      fb5(DRIVER, &draiosproto::feature_status::set_driver_enabled, {}, fm),
	      fb6(SECURE, &draiosproto::feature_status::set_secure_enabled, {}, fm),
	      fb7(COMMAND_LINE_CAPTURE,
	          &draiosproto::feature_status::set_commandline_capture_enabled,
	          {},
	          fm),
	      fb8(BASELINER, &draiosproto::feature_status::set_baseliner_enabled, {}, fm),
	      fb9(MEMDUMP, &draiosproto::feature_status::set_memdump_enabled, {}, fm),
	      fb10(SECURE_AUDIT, &draiosproto::feature_status::set_secure_audit_enabled, {}, fm),
	      fb11(FULL_SYSCALLS, &draiosproto::feature_status::set_full_syscalls_enabled, {}, fm),
	      fb12(NETWORK_BREAKDOWN,
	           &draiosproto::feature_status::set_network_breakdown_enabled,
	           {FULL_SYSCALLS},
	           fm),
	      fb13(FILE_BREAKDOWN,
	           &draiosproto::feature_status::set_file_breakdown_enabled,
	           {NETWORK_BREAKDOWN},
	           fm),
	      fb14(PROTOCOL_STATS,
	           &draiosproto::feature_status::set_protocol_stats_enabled,
	           {FILE_BREAKDOWN},
	           fm),
	      fb15(HTTP_STATS, &draiosproto::feature_status::set_http_stats_enabled, {}, fm),
	      fb16(MYSQL_STATS, &draiosproto::feature_status::set_mysql_stats_enabled, {}, fm),
	      fb17(POSTGRES_STATS, &draiosproto::feature_status::set_postgres_stats_enabled, {}, fm),
	      fb18(MONGODB_STATS, &draiosproto::feature_status::set_mongodb_stats_enabled, {}, fm),
	      fb19(MONITOR, &draiosproto::feature_status::set_monitor_enabled, {}, fm)
	{
	}

	// This just provides us with a constructor to create the features with no deps.
	// The ultimate issue was we were trying to initialize features with the dummy deps,
	// but then we can't initialize some of the modes properly. so we just create
	// a constructor that gives us a more relaxed version of dependencies
	dummy_features(feature_manager& fm, bool no_deps)
	    : fb0(PROMETHEUS, &draiosproto::feature_status::set_prometheus_enabled, {}, fm),
	      fb1(STATSD, &draiosproto::feature_status::set_statsd_enabled, {}, fm),
	      fb2(JMX, &draiosproto::feature_status::set_jmx_enabled, {}, fm),
	      fb3(APP_CHECKS, &draiosproto::feature_status::set_app_checks_enabled, {}, fm),
	      fb4(COINTERFACE, &draiosproto::feature_status::set_cointerface_enabled, {}, fm),
	      fb5(DRIVER, &draiosproto::feature_status::set_driver_enabled, {}, fm),
	      fb6(SECURE, &draiosproto::feature_status::set_secure_enabled, {}, fm),
	      fb7(COMMAND_LINE_CAPTURE,
	          &draiosproto::feature_status::set_commandline_capture_enabled,
	          {},
	          fm),
	      fb8(BASELINER, &draiosproto::feature_status::set_baseliner_enabled, {}, fm),
	      fb9(MEMDUMP, &draiosproto::feature_status::set_memdump_enabled, {}, fm),
	      fb10(SECURE_AUDIT, &draiosproto::feature_status::set_secure_audit_enabled, {}, fm),
	      fb11(FULL_SYSCALLS, &draiosproto::feature_status::set_full_syscalls_enabled, {}, fm),
	      fb12(NETWORK_BREAKDOWN,
	           &draiosproto::feature_status::set_network_breakdown_enabled,
	           {},
	           fm),
	      fb13(FILE_BREAKDOWN, &draiosproto::feature_status::set_file_breakdown_enabled, {}, fm),
	      fb14(PROTOCOL_STATS, &draiosproto::feature_status::set_protocol_stats_enabled, {}, fm),
	      fb15(HTTP_STATS, &draiosproto::feature_status::set_http_stats_enabled, {}, fm),
	      fb16(MYSQL_STATS, &draiosproto::feature_status::set_mysql_stats_enabled, {}, fm),
	      fb17(POSTGRES_STATS, &draiosproto::feature_status::set_postgres_stats_enabled, {}, fm),
	      fb18(MONGODB_STATS, &draiosproto::feature_status::set_mongodb_stats_enabled, {}, fm),
	      fb19(MONITOR, &draiosproto::feature_status::set_monitor_enabled, {}, fm)
	{
	}

	feature_base fb0;
	feature_base fb1;
	feature_base fb2;
	feature_base fb3;
	feature_base fb4;
	feature_base fb5;
	feature_base fb6;
	feature_base fb7;
	feature_base fb8;
	feature_base fb9;
	feature_base fb10;
	feature_base fb11;
	feature_base fb12;
	feature_base fb13;
	feature_base fb14;
	feature_base fb15;
	feature_base fb16;
	feature_base fb17;
	feature_base fb18;
	feature_base fb19;
};

}  // namespace

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
	dummy_features df(fm, true);

	EXPECT_TRUE(fm.initialize());

	df.fb0.set_enabled(false);
	EXPECT_FALSE(fm.get_enabled((feature_name)0));
	df.fb0.set_enabled(true);
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
	feature_base fb12((feature_name)12,
	                  &draiosproto::feature_status::set_prometheus_enabled,
	                  {},
	                  fm);
	feature_base fb13((feature_name)13,
	                  &draiosproto::feature_status::set_prometheus_enabled,
	                  {},
	                  fm);
	feature_base fb14((feature_name)14,
	                  &draiosproto::feature_status::set_prometheus_enabled,
	                  {},
	                  fm);
	feature_base fb15(HTTP_STATS, &draiosproto::feature_status::set_http_stats_enabled, {}, fm);
	feature_base fb16(MYSQL_STATS, &draiosproto::feature_status::set_mysql_stats_enabled, {}, fm);
	feature_base fb17(POSTGRES_STATS,
	                  &draiosproto::feature_status::set_postgres_stats_enabled,
	                  {},
	                  fm);
	feature_base fb18(MONGODB_STATS,
	                  &draiosproto::feature_status::set_mongodb_stats_enabled,
	                  {},
	                  fm);
	feature_base fb19(MONITOR,
	                  &draiosproto::feature_status::set_mongodb_stats_enabled,
	                  {},
	                  fm);

	test_helpers::scoped_config<bool> memdump("prometheus.enabled", true);
	ASSERT_FALSE(fb.m_init_called);
	EXPECT_TRUE(fm.initialize());
	ASSERT_TRUE(fb.m_init_called);
}

TEST(feature_manager, base_deprecated_disable)
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

	EXPECT_TRUE(fm.deprecated_disable((feature_name)1));
	EXPECT_FALSE(fm.get_enabled((feature_name)1));

	empty_dep.set_enabled(true);
	some_dep.set_enabled(true);

	EXPECT_FALSE(fm.deprecated_disable((feature_name)1));
	EXPECT_TRUE(fm.get_enabled((feature_name)1));
}

TEST(feature_manager, validate_dependencies)
{
	feature_manager fm;

	feature_base enabled((feature_name)0, nullptr, {}, fm);
	enabled.set_enabled(true);
	EXPECT_TRUE(test_helper::verify_dependencies(fm));

	feature_base disabled((feature_name)1, nullptr, {}, fm);
	disabled.set_enabled(false);
	EXPECT_TRUE(test_helper::verify_dependencies(fm));

	feature_base enabled_with_met_dependency((feature_name)2, nullptr, {(feature_name)0}, fm);
	enabled_with_met_dependency.set_enabled(true);
	EXPECT_TRUE(test_helper::verify_dependencies(fm));

	feature_base disabled_with_unmet_dependencies((feature_name)3, nullptr, {(feature_name)1}, fm);
	disabled_with_unmet_dependencies.set_enabled(false);
	EXPECT_TRUE(test_helper::verify_dependencies(fm));

	feature_base enabled_with_unmet_dependencies((feature_name)4, nullptr, {(feature_name)1}, fm);
	enabled_with_unmet_dependencies.set_enabled(true);
	EXPECT_FALSE(test_helper::verify_dependencies(fm));
}

TEST(feature_manager, enable)
{
	feature_manager fm;

	feature_base fb0(PROMETHEUS, nullptr, {}, fm);
	fb0.set_enabled(false);
	scoped_config<bool> config("prometheus.enabled", true);

	EXPECT_TRUE(test_helper::enable(fm, PROMETHEUS, false));
	EXPECT_TRUE(fb0.get_enabled());
	EXPECT_TRUE(fb0.locked());
}

TEST(feature_manager, enable_caller_locked_on)
{
	feature_manager fm;

	feature_base fb0(PROMETHEUS, nullptr, {}, fm);
	fb0.set_enabled(true);
	fb0.set_locked();

	scoped_config<bool> config("prometheus.enabled", true);

	EXPECT_TRUE(test_helper::enable(fm, PROMETHEUS, false));
	EXPECT_TRUE(fb0.get_enabled());
	EXPECT_TRUE(fb0.locked());
}

TEST(feature_manager, enable_caller_locked_off)
{
	feature_manager fm;

	feature_base fb0(PROMETHEUS, nullptr, {}, fm);
	fb0.set_enabled(false);
	fb0.set_locked();

	scoped_config<bool> config("prometheus.enabled", true);

	EXPECT_FALSE(test_helper::enable(fm, PROMETHEUS, false));
}

TEST(feature_manager, enable_dependency_locked_on)
{
	feature_manager fm;

	feature_base dep(STATSD, nullptr, {}, fm);
	dep.set_enabled(true);
	dep.set_locked();
	feature_base fb0(PROMETHEUS, nullptr, {STATSD}, fm);

	scoped_config<bool> config("prometheus.enabled", true);

	EXPECT_TRUE(test_helper::enable(fm, PROMETHEUS, false));
	EXPECT_TRUE(fb0.get_enabled());
	EXPECT_TRUE(fb0.locked());
}

TEST(feature_manager, enable_dependency_locked_off)
{
	feature_manager fm;

	feature_base dep(STATSD, nullptr, {}, fm);
	dep.set_enabled(false);
	dep.set_locked();
	feature_base fb0(PROMETHEUS, nullptr, {STATSD}, fm);

	scoped_config<bool> config("prometheus.enabled", true);

	EXPECT_FALSE(test_helper::enable(fm, PROMETHEUS, false));
}

TEST(feature_manager, enable_dependency_not_locked_on)
{
	feature_manager fm;

	feature_base dep(STATSD, nullptr, {}, fm);
	dep.set_enabled(true);
	feature_base fb0(PROMETHEUS, nullptr, {STATSD}, fm);

	scoped_config<bool> config("prometheus.enabled", true);

	EXPECT_TRUE(test_helper::enable(fm, PROMETHEUS, false));
	EXPECT_TRUE(fb0.get_enabled());
	EXPECT_TRUE(fb0.locked());
	EXPECT_TRUE(dep.get_enabled());
	EXPECT_TRUE(dep.locked());
}

TEST(feature_manager, enable_dependency_not_locked_off)
{
	feature_manager fm;

	feature_base dep(STATSD, nullptr, {}, fm);
	dep.set_enabled(false);
	feature_base fb0(PROMETHEUS, nullptr, {STATSD}, fm);

	scoped_config<bool> config("prometheus.enabled", true);

	EXPECT_FALSE(test_helper::enable(fm, PROMETHEUS, false));
}

TEST(feature_manager, enable_dependency_not_locked_off_enableable)
{
	feature_manager fm;

	feature_base dep(STATSD, nullptr, {}, fm);
	dep.set_enabled(false);
	scoped_config<bool> config2("statsd.enabled", true);
	feature_base fb0(PROMETHEUS, nullptr, {STATSD}, fm);

	scoped_config<bool> config("prometheus.enabled", true);

	EXPECT_TRUE(test_helper::enable(fm, PROMETHEUS, false));
	EXPECT_TRUE(fb0.get_enabled());
	EXPECT_TRUE(fb0.locked());
	EXPECT_TRUE(dep.get_enabled());
	EXPECT_TRUE(dep.locked());
}

TEST(feature_manager, enable_dependency_chained)
{
	feature_manager fm;

	// put a couple at the top of the chain, one locked, one non
	feature_base leaf_dep_locked(STATSD, nullptr, {}, fm);
	leaf_dep_locked.set_enabled(true);
	leaf_dep_locked.set_locked();

	feature_base leaf_dep_unlocked(JMX, nullptr, {}, fm);
	leaf_dep_unlocked.set_enabled(true);

	// put one that calls both of them and has multiple children
	feature_base multi_parent(APP_CHECKS, nullptr, {STATSD, JMX}, fm);
	multi_parent.set_enabled(true);

	// put one that is weakly enableable
	feature_base weak(COINTERFACE, nullptr, {APP_CHECKS}, fm);
	weak.set_enabled(false);
	scoped_config<bool> c1("cointerface_enabled", true);
	scoped_config<bool> c2("cointerface_enabled_opt.weak", true);

	// one that is regularly enableable
	feature_base regular(DRIVER, nullptr, {COINTERFACE, APP_CHECKS}, fm);
	regular.set_enabled(false);
	scoped_config<bool> c3("feature.driver", true);

	feature_base fb0(PROMETHEUS, nullptr, {DRIVER}, fm);
	scoped_config<bool> c4("prometheus.enabled", true);

	EXPECT_TRUE(test_helper::enable(fm, PROMETHEUS, false));
	EXPECT_TRUE(leaf_dep_locked.get_enabled());
	EXPECT_TRUE(leaf_dep_locked.locked());
	EXPECT_TRUE(leaf_dep_unlocked.get_enabled());
	EXPECT_TRUE(leaf_dep_unlocked.locked());
	EXPECT_TRUE(multi_parent.get_enabled());
	EXPECT_TRUE(multi_parent.locked());
	EXPECT_TRUE(weak.get_enabled());
	EXPECT_TRUE(weak.locked());
	EXPECT_TRUE(regular.get_enabled());
	EXPECT_TRUE(regular.locked());
	EXPECT_TRUE(fb0.get_enabled());
	EXPECT_TRUE(fb0.locked());
}

TEST(feature_manager, enable_dependency_chained_fail)
{
	feature_manager fm;

	// put a couple at the top of the chain, one locked, one non
	feature_base leaf_dep_locked(STATSD, nullptr, {}, fm);
	leaf_dep_locked.set_enabled(true);
	leaf_dep_locked.set_locked();

	feature_base leaf_dep_unlocked(JMX, nullptr, {}, fm);
	leaf_dep_unlocked.set_enabled(false);

	// put one that calls both of them and has multiple children
	feature_base multi_parent(APP_CHECKS, nullptr, {STATSD, JMX}, fm);
	multi_parent.set_enabled(true);

	// put one that is weakly enableable
	feature_base weak(COINTERFACE, nullptr, {APP_CHECKS}, fm);
	weak.set_enabled(false);
	scoped_config<bool> c1("cointerface_enabled", true);
	scoped_config<bool> c2("cointerface_enabled_opt.weak", true);

	// one that is regularly enableable
	feature_base regular(DRIVER, nullptr, {COINTERFACE, APP_CHECKS}, fm);
	regular.set_enabled(false);
	scoped_config<bool> c3("feature.driver", true);

	feature_base fb0(PROMETHEUS, nullptr, {DRIVER}, fm);
	scoped_config<bool> c4("prometheus.enabled", true);

	EXPECT_FALSE(test_helper::enable(fm, PROMETHEUS, false));
}

TEST(feature_manager, enable_force)
{
	feature_manager fm;

	feature_base fb0(PROMETHEUS, nullptr, {}, fm);
	fb0.set_enabled(false);
	scoped_config<bool> config("prometheus.enabled", true);

	EXPECT_TRUE(test_helper::enable(fm, PROMETHEUS, true));
	EXPECT_TRUE(fb0.get_enabled());
	EXPECT_TRUE(fb0.locked());
}

TEST(feature_manager, enable_caller_locked_on_force)
{
	feature_manager fm;

	feature_base fb0(PROMETHEUS, nullptr, {}, fm);
	fb0.set_enabled(true);
	fb0.set_locked();

	scoped_config<bool> config("prometheus.enabled", true);

	EXPECT_TRUE(test_helper::enable(fm, PROMETHEUS, true));
	EXPECT_TRUE(fb0.get_enabled());
	EXPECT_TRUE(fb0.locked());
}

TEST(feature_manager, enable_caller_locked_off_force)
{
	feature_manager fm;

	feature_base fb0(PROMETHEUS, nullptr, {}, fm);
	fb0.set_enabled(false);
	fb0.set_locked();

	scoped_config<bool> config("prometheus.enabled", true);

	EXPECT_FALSE(test_helper::enable(fm, PROMETHEUS, true));
}

TEST(feature_manager, enable_dependency_locked_on_force)
{
	feature_manager fm;

	feature_base dep(STATSD, nullptr, {}, fm);
	dep.set_enabled(true);
	dep.set_locked();
	feature_base fb0(PROMETHEUS, nullptr, {STATSD}, fm);

	scoped_config<bool> config("prometheus.enabled", true);

	EXPECT_TRUE(test_helper::enable(fm, PROMETHEUS, true));
	EXPECT_TRUE(fb0.get_enabled());
	EXPECT_TRUE(fb0.locked());
}

TEST(feature_manager, enable_dependency_locked_off_force)
{
	feature_manager fm;

	feature_base dep(STATSD, nullptr, {}, fm);
	dep.set_enabled(false);
	dep.set_locked();
	feature_base fb0(PROMETHEUS, nullptr, {STATSD}, fm);

	scoped_config<bool> config("prometheus.enabled", true);

	EXPECT_FALSE(test_helper::enable(fm, PROMETHEUS, true));
}

TEST(feature_manager, enable_dependency_not_locked_on_force)
{
	feature_manager fm;

	feature_base dep(STATSD, nullptr, {}, fm);
	dep.set_enabled(true);
	feature_base fb0(PROMETHEUS, nullptr, {STATSD}, fm);

	scoped_config<bool> config("prometheus.enabled", true);

	EXPECT_TRUE(test_helper::enable(fm, PROMETHEUS, true));
	EXPECT_TRUE(fb0.get_enabled());
	EXPECT_TRUE(fb0.locked());
	EXPECT_TRUE(dep.get_enabled());
	EXPECT_TRUE(dep.locked());
}

TEST(feature_manager, enable_dependency_not_locked_off_force)
{
	feature_manager fm;

	feature_base dep(STATSD, nullptr, {}, fm);
	dep.set_enabled(false);
	feature_base fb0(PROMETHEUS, nullptr, {STATSD}, fm);

	scoped_config<bool> config("prometheus.enabled", true);

	EXPECT_TRUE(test_helper::enable(fm, PROMETHEUS, true));
	EXPECT_TRUE(fb0.get_enabled());
	EXPECT_TRUE(fb0.locked());
	EXPECT_TRUE(dep.get_enabled());
	EXPECT_TRUE(dep.locked());
}

TEST(feature_manager, enable_dependency_not_locked_off_enableable_force)
{
	feature_manager fm;

	feature_base dep(STATSD, nullptr, {}, fm);
	dep.set_enabled(false);
	scoped_config<bool> config2("statsd.enabled", true);
	feature_base fb0(PROMETHEUS, nullptr, {STATSD}, fm);

	scoped_config<bool> config("prometheus.enabled", true);

	EXPECT_TRUE(test_helper::enable(fm, PROMETHEUS, true));
	EXPECT_TRUE(fb0.get_enabled());
	EXPECT_TRUE(fb0.locked());
	EXPECT_TRUE(dep.get_enabled());
	EXPECT_TRUE(dep.locked());
}

TEST(feature_manager, enable_dependency_chained_force)
{
	feature_manager fm;

	// put a couple at the top of the chain, one locked, one non
	feature_base leaf_dep_locked(STATSD, nullptr, {}, fm);
	leaf_dep_locked.set_enabled(true);
	leaf_dep_locked.set_locked();

	feature_base leaf_dep_unlocked(JMX, nullptr, {}, fm);

	// put one that calls both of them and has multiple children
	feature_base multi_parent(APP_CHECKS, nullptr, {STATSD, JMX}, fm);

	// put one that is weakly enableable
	feature_base weak(COINTERFACE, nullptr, {APP_CHECKS}, fm);
	weak.set_enabled(false);
	scoped_config<bool> c1("cointerface_enabled", true);
	scoped_config<bool> c2("cointerface_enabled_opt.weak", true);

	// one that needs to be force enabled
	feature_base regular(DRIVER, nullptr, {COINTERFACE, APP_CHECKS}, fm);
	regular.set_enabled(false);

	feature_base fb0(PROMETHEUS, nullptr, {DRIVER}, fm);
	scoped_config<bool> c4("prometheus.enabled", true);

	EXPECT_TRUE(test_helper::enable(fm, PROMETHEUS, true));
	EXPECT_TRUE(leaf_dep_locked.get_enabled());
	EXPECT_TRUE(leaf_dep_locked.locked());
	EXPECT_TRUE(leaf_dep_unlocked.get_enabled());
	EXPECT_TRUE(leaf_dep_unlocked.locked());
	EXPECT_TRUE(multi_parent.get_enabled());
	EXPECT_TRUE(multi_parent.locked());
	EXPECT_TRUE(weak.get_enabled());
	EXPECT_TRUE(weak.locked());
	EXPECT_TRUE(regular.get_enabled());
	EXPECT_TRUE(regular.locked());
	EXPECT_TRUE(fb0.get_enabled());
	EXPECT_TRUE(fb0.locked());
}

TEST(feature_manager, enable_dependency_chained_force_fail)
{
	feature_manager fm;

	// put a couple at the top of the chain, one locked, one non
	feature_base leaf_dep_locked(STATSD, nullptr, {}, fm);
	leaf_dep_locked.set_enabled(false);
	leaf_dep_locked.set_locked();

	feature_base leaf_dep_unlocked(JMX, nullptr, {}, fm);

	// put one that calls both of them and has multiple children
	feature_base multi_parent(APP_CHECKS, nullptr, {STATSD, JMX}, fm);

	// put one that is weakly enableable
	feature_base weak(COINTERFACE, nullptr, {APP_CHECKS}, fm);
	weak.set_enabled(false);
	scoped_config<bool> c1("cointerface_enabled", true);
	scoped_config<bool> c2("cointerface_enabled_opt.weak", true);

	// one that needs to be force enabled
	feature_base regular(DRIVER, nullptr, {COINTERFACE, APP_CHECKS}, fm);
	regular.set_enabled(false);

	feature_base fb0(PROMETHEUS, nullptr, {DRIVER}, fm);
	scoped_config<bool> c4("prometheus.enabled", true);

	EXPECT_FALSE(test_helper::enable(fm, PROMETHEUS, true));
}

TEST(feature_manager, disable)
{
	feature_manager fm;

	feature_base fb0(PROMETHEUS, nullptr, {}, fm);
	fb0.set_enabled(true);
	scoped_config<bool> config("prometheus.enabled", false);

	EXPECT_TRUE(test_helper::disable(fm, PROMETHEUS, false));
	EXPECT_FALSE(fb0.get_enabled());
	EXPECT_TRUE(fb0.locked());
}

TEST(feature_manager, disable_caller_locked_on)
{
	feature_manager fm;

	feature_base fb0(PROMETHEUS, nullptr, {}, fm);
	fb0.set_enabled(true);
	fb0.set_locked();

	scoped_config<bool> config("prometheus.enabled", false);

	EXPECT_FALSE(test_helper::disable(fm, PROMETHEUS, false));
}

TEST(feature_manager, disable_caller_locked_off)
{
	feature_manager fm;

	feature_base fb0(PROMETHEUS, nullptr, {}, fm);
	fb0.set_enabled(false);
	fb0.set_locked();

	scoped_config<bool> config("prometheus.enabled", false);

	EXPECT_TRUE(test_helper::disable(fm, PROMETHEUS, false));
	EXPECT_FALSE(fb0.get_enabled());
	EXPECT_TRUE(fb0.locked());
}

TEST(feature_manager, disable_dependency_locked_on)
{
	feature_manager fm;

	feature_base dep(STATSD, nullptr, {PROMETHEUS}, fm);
	dep.set_enabled(true);
	dep.set_locked();
	feature_base fb0(PROMETHEUS, nullptr, {}, fm);

	scoped_config<bool> config("prometheus.enabled", false);

	EXPECT_FALSE(test_helper::disable(fm, PROMETHEUS, false));
}

TEST(feature_manager, disable_dependency_locked_off)
{
	feature_manager fm;

	feature_base dep(STATSD, nullptr, {PROMETHEUS}, fm);
	dep.set_enabled(false);
	dep.set_locked();
	feature_base fb0(PROMETHEUS, nullptr, {}, fm);

	scoped_config<bool> config("prometheus.enabled", false);

	EXPECT_TRUE(test_helper::disable(fm, PROMETHEUS, false));
	EXPECT_FALSE(fb0.get_enabled());
	EXPECT_TRUE(fb0.locked());
}

TEST(feature_manager, disable_dependency_not_locked_on)
{
	feature_manager fm;

	feature_base dep(STATSD, nullptr, {PROMETHEUS}, fm);
	dep.set_enabled(true);
	feature_base fb0(PROMETHEUS, nullptr, {}, fm);

	scoped_config<bool> config("prometheus.enabled", false);

	EXPECT_FALSE(test_helper::disable(fm, PROMETHEUS, false));
}

TEST(feature_manager, disable_dependency_not_locked_off)
{
	feature_manager fm;

	feature_base dep(STATSD, nullptr, {PROMETHEUS}, fm);
	dep.set_enabled(false);
	feature_base fb0(PROMETHEUS, nullptr, {}, fm);

	scoped_config<bool> config("prometheus.enabled", false);

	EXPECT_TRUE(test_helper::disable(fm, PROMETHEUS, false));
	EXPECT_FALSE(fb0.get_enabled());
	EXPECT_TRUE(fb0.locked());
	EXPECT_FALSE(dep.get_enabled());
	EXPECT_TRUE(dep.locked());
}

TEST(feature_manager, disable_dependency_not_locked_on_disableable)
{
	feature_manager fm;

	feature_base dep(STATSD, nullptr, {PROMETHEUS}, fm);
	dep.set_enabled(true);
	scoped_config<bool> config2("statsd.enabled", false);
	feature_base fb0(PROMETHEUS, nullptr, {}, fm);

	scoped_config<bool> config("prometheus.enabled", false);

	EXPECT_TRUE(test_helper::disable(fm, PROMETHEUS, false));
	EXPECT_FALSE(fb0.get_enabled());
	EXPECT_TRUE(fb0.locked());
	EXPECT_FALSE(dep.get_enabled());
	EXPECT_TRUE(dep.locked());
}

TEST(feature_manager, disable_dependency_chained)
{
	feature_manager fm;

	// put a couple at the top of the chain, one locked, one non
	feature_base leaf_dep_locked(STATSD, nullptr, {APP_CHECKS}, fm);
	leaf_dep_locked.set_enabled(false);
	leaf_dep_locked.set_locked();

	feature_base leaf_dep_unlocked(JMX, nullptr, {APP_CHECKS}, fm);
	leaf_dep_unlocked.set_enabled(false);

	// put one that calls both of them and has multiple children
	feature_base multi_parent(APP_CHECKS, nullptr, {COINTERFACE, DRIVER}, fm);
	multi_parent.set_enabled(false);

	// put one that is weakly enableable
	feature_base weak(COINTERFACE, nullptr, {DRIVER}, fm);
	weak.set_enabled(true);
	scoped_config<bool> c1("cointerface_enabled", false);
	scoped_config<bool> c2("cointerface_enabled_opt.weak", true);

	// one that is regularly enableable
	feature_base regular(DRIVER, nullptr, {PROMETHEUS}, fm);
	regular.set_enabled(true);
	scoped_config<bool> c3("feature.driver", false);

	feature_base fb0(PROMETHEUS, nullptr, {}, fm);
	scoped_config<bool> c4("prometheus.enabled", false);

	EXPECT_TRUE(test_helper::disable(fm, PROMETHEUS, false));
	EXPECT_FALSE(leaf_dep_locked.get_enabled());
	EXPECT_TRUE(leaf_dep_locked.locked());
	EXPECT_FALSE(leaf_dep_unlocked.get_enabled());
	EXPECT_TRUE(leaf_dep_unlocked.locked());
	EXPECT_FALSE(multi_parent.get_enabled());
	EXPECT_TRUE(multi_parent.locked());
	EXPECT_FALSE(weak.get_enabled());
	EXPECT_TRUE(weak.locked());
	EXPECT_FALSE(regular.get_enabled());
	EXPECT_TRUE(regular.locked());
	EXPECT_FALSE(fb0.get_enabled());
	EXPECT_TRUE(fb0.locked());
}

TEST(feature_manager, disable_dependency_chained_fail)
{
	feature_manager fm;

	// put a couple at the top of the chain, one locked, one non
	feature_base leaf_dep_locked(STATSD, nullptr, {APP_CHECKS}, fm);
	leaf_dep_locked.set_enabled(false);
	leaf_dep_locked.set_locked();

	feature_base leaf_dep_unlocked(JMX, nullptr, {APP_CHECKS}, fm);
	leaf_dep_unlocked.set_enabled(true);

	// put one that calls both of them and has multiple children
	feature_base multi_parent(APP_CHECKS, nullptr, {COINTERFACE, DRIVER}, fm);
	multi_parent.set_enabled(false);

	// put one that is weakly enableable
	feature_base weak(COINTERFACE, nullptr, {DRIVER}, fm);
	weak.set_enabled(true);
	scoped_config<bool> c1("cointerface_enabled", false);
	scoped_config<bool> c2("cointerface_enabled_opt.weak", true);

	// one that is regularly enableable
	feature_base regular(DRIVER, nullptr, {PROMETHEUS}, fm);
	regular.set_enabled(true);
	scoped_config<bool> c3("feature.driver", false);

	feature_base fb0(PROMETHEUS, nullptr, {}, fm);
	scoped_config<bool> c4("prometheus.enabled", false);

	EXPECT_FALSE(test_helper::disable(fm, PROMETHEUS, false));
}

TEST(feature_manager, disable_force)
{
	feature_manager fm;

	feature_base fb0(PROMETHEUS, nullptr, {}, fm);
	fb0.set_enabled(true);
	scoped_config<bool> config("prometheus.enabled", false);

	EXPECT_TRUE(test_helper::disable(fm, PROMETHEUS, true));
	EXPECT_FALSE(fb0.get_enabled());
	EXPECT_TRUE(fb0.locked());
}

TEST(feature_manager, disable_caller_locked_on_force)
{
	feature_manager fm;

	feature_base fb0(PROMETHEUS, nullptr, {}, fm);
	fb0.set_enabled(true);
	fb0.set_locked();

	scoped_config<bool> config("prometheus.enabled", true);

	EXPECT_FALSE(test_helper::disable(fm, PROMETHEUS, false));
}

TEST(feature_manager, disable_caller_locked_off_force)
{
	feature_manager fm;

	feature_base fb0(PROMETHEUS, nullptr, {}, fm);
	fb0.set_enabled(false);
	fb0.set_locked();

	scoped_config<bool> config("prometheus.enabled", false);

	EXPECT_TRUE(test_helper::disable(fm, PROMETHEUS, true));
	EXPECT_FALSE(fb0.get_enabled());
	EXPECT_TRUE(fb0.locked());
}

TEST(feature_manager, disable_dependency_locked_on_force)
{
	feature_manager fm;

	feature_base dep(STATSD, nullptr, {PROMETHEUS}, fm);
	dep.set_enabled(true);
	dep.set_locked();
	feature_base fb0(PROMETHEUS, nullptr, {}, fm);

	scoped_config<bool> config("prometheus.enabled", false);

	EXPECT_FALSE(test_helper::disable(fm, PROMETHEUS, true));
}

TEST(feature_manager, disable_dependency_locked_off_force)
{
	feature_manager fm;

	feature_base dep(STATSD, nullptr, {PROMETHEUS}, fm);
	dep.set_enabled(false);
	dep.set_locked();
	feature_base fb0(PROMETHEUS, nullptr, {}, fm);

	scoped_config<bool> config("prometheus.enabled", false);

	EXPECT_TRUE(test_helper::disable(fm, PROMETHEUS, true));
	EXPECT_FALSE(fb0.get_enabled());
	EXPECT_TRUE(fb0.locked());
}

TEST(feature_manager, disable_dependency_not_locked_on_force)
{
	feature_manager fm;

	feature_base dep(STATSD, nullptr, {PROMETHEUS}, fm);
	dep.set_enabled(true);
	feature_base fb0(PROMETHEUS, nullptr, {}, fm);

	scoped_config<bool> config("prometheus.enabled", false);

	EXPECT_TRUE(test_helper::disable(fm, PROMETHEUS, true));
	EXPECT_FALSE(fb0.get_enabled());
	EXPECT_TRUE(fb0.locked());
	EXPECT_FALSE(dep.get_enabled());
	EXPECT_TRUE(dep.locked());
}

TEST(feature_manager, disable_dependency_not_locked_off_force)
{
	feature_manager fm;

	feature_base dep(STATSD, nullptr, {PROMETHEUS}, fm);
	dep.set_enabled(false);
	feature_base fb0(PROMETHEUS, nullptr, {}, fm);

	scoped_config<bool> config("prometheus.enabled", false);

	EXPECT_TRUE(test_helper::disable(fm, PROMETHEUS, true));
	EXPECT_FALSE(fb0.get_enabled());
	EXPECT_TRUE(fb0.locked());
	EXPECT_FALSE(dep.get_enabled());
	EXPECT_TRUE(dep.locked());
}

TEST(feature_manager, disable_dependency_not_locked_on_disableable_force)
{
	feature_manager fm;

	feature_base dep(STATSD, nullptr, {PROMETHEUS}, fm);
	dep.set_enabled(true);
	scoped_config<bool> config2("statsd.enabled", false);
	feature_base fb0(PROMETHEUS, nullptr, {}, fm);

	scoped_config<bool> config("prometheus.enabled", false);

	EXPECT_TRUE(test_helper::disable(fm, PROMETHEUS, true));
	EXPECT_FALSE(fb0.get_enabled());
	EXPECT_TRUE(fb0.locked());
	EXPECT_FALSE(dep.get_enabled());
	EXPECT_TRUE(dep.locked());
}

TEST(feature_manager, disable_dependency_chained_force)
{
	feature_manager fm;

	// put a couple at the top of the chain, one locked, one non
	feature_base leaf_dep_locked(STATSD, nullptr, {APP_CHECKS}, fm);
	leaf_dep_locked.set_enabled(false);
	leaf_dep_locked.set_locked();

	feature_base leaf_dep_unlocked(JMX, nullptr, {APP_CHECKS}, fm);

	// put one that calls both of them and has multiple children
	feature_base multi_parent(APP_CHECKS, nullptr, {COINTERFACE, DRIVER}, fm);

	// put one that is weakly enableable
	feature_base weak(COINTERFACE, nullptr, {DRIVER}, fm);
	weak.set_enabled(true);
	scoped_config<bool> c1("cointerface_enabled", false);
	scoped_config<bool> c2("cointerface_enabled_opt.weak", true);

	// one that is regularly enableable
	feature_base regular(DRIVER, nullptr, {PROMETHEUS}, fm);
	regular.set_enabled(false);

	feature_base fb0(PROMETHEUS, nullptr, {}, fm);
	scoped_config<bool> c4("prometheus.enabled", false);

	EXPECT_TRUE(test_helper::disable(fm, PROMETHEUS, false));
	EXPECT_FALSE(leaf_dep_locked.get_enabled());
	EXPECT_TRUE(leaf_dep_locked.locked());
	EXPECT_FALSE(leaf_dep_unlocked.get_enabled());
	EXPECT_TRUE(leaf_dep_unlocked.locked());
	EXPECT_FALSE(multi_parent.get_enabled());
	EXPECT_TRUE(multi_parent.locked());
	EXPECT_FALSE(weak.get_enabled());
	EXPECT_TRUE(weak.locked());
	EXPECT_FALSE(regular.get_enabled());
	EXPECT_TRUE(regular.locked());
	EXPECT_FALSE(fb0.get_enabled());
	EXPECT_TRUE(fb0.locked());
}

TEST(feature_manager, disable_dependency_chained_force_fail)
{
	feature_manager fm;

	// put a couple at the top of the chain, one locked, one non
	feature_base leaf_dep_locked(STATSD, nullptr, {APP_CHECKS}, fm);
	leaf_dep_locked.set_enabled(true);
	leaf_dep_locked.set_locked();

	feature_base leaf_dep_unlocked(JMX, nullptr, {APP_CHECKS}, fm);

	// put one that calls both of them and has multiple children
	feature_base multi_parent(APP_CHECKS, nullptr, {COINTERFACE, DRIVER}, fm);

	// put one that is weakly enableable
	feature_base weak(COINTERFACE, nullptr, {DRIVER}, fm);
	weak.set_enabled(true);
	scoped_config<bool> c1("cointerface_enabled", false);
	scoped_config<bool> c2("cointerface_enabled_opt.weak", true);

	// one that is regularly enableable
	feature_base regular(DRIVER, nullptr, {PROMETHEUS}, fm);
	regular.set_enabled(true);

	feature_base fb0(PROMETHEUS, nullptr, {}, fm);
	scoped_config<bool> c4("prometheus.enabled", false);

	EXPECT_FALSE(test_helper::disable(fm, PROMETHEUS, true));
}

TEST(feature_manager, enable_try)
{
	feature_manager fm;

	feature_base fb0(PROMETHEUS, nullptr, {}, fm);
	fb0.set_enabled(false);
	scoped_config<bool> config("prometheus.enabled", true);

	EXPECT_TRUE(test_helper::try_enable(fm, PROMETHEUS));
	EXPECT_TRUE(fb0.get_enabled());
	EXPECT_TRUE(fb0.locked());
}

TEST(feature_manager, enable_caller_locked_on_try)
{
	feature_manager fm;

	feature_base fb0(PROMETHEUS, nullptr, {}, fm);
	fb0.set_enabled(true);
	fb0.set_locked();

	scoped_config<bool> config("prometheus.enabled", true);

	EXPECT_TRUE(test_helper::try_enable(fm, PROMETHEUS));
	EXPECT_TRUE(fb0.get_enabled());
	EXPECT_TRUE(fb0.locked());
}

TEST(feature_manager, enable_caller_locked_off_try)
{
	feature_manager fm;

	feature_base fb0(PROMETHEUS, nullptr, {}, fm);
	fb0.set_enabled(false);
	fb0.set_locked();

	scoped_config<bool> config("prometheus.enabled", true);

	EXPECT_FALSE(test_helper::try_enable(fm, PROMETHEUS));
}

TEST(feature_manager, enable_dependency_locked_on_try)
{
	feature_manager fm;

	feature_base dep(STATSD, nullptr, {}, fm);
	dep.set_enabled(true);
	dep.set_locked();
	feature_base fb0(PROMETHEUS, nullptr, {STATSD}, fm);

	scoped_config<bool> config("prometheus.enabled", true);

	EXPECT_TRUE(test_helper::try_enable(fm, PROMETHEUS));
	EXPECT_TRUE(fb0.get_enabled());
	EXPECT_TRUE(fb0.locked());
}

TEST(feature_manager, enable_dependency_locked_off_try)
{
	feature_manager fm;

	feature_base dep(STATSD, nullptr, {}, fm);
	dep.set_enabled(false);
	dep.set_locked();
	feature_base fb0(PROMETHEUS, nullptr, {STATSD}, fm);

	scoped_config<bool> config("prometheus.enabled", true);

	EXPECT_FALSE(test_helper::try_enable(fm, PROMETHEUS));
}

TEST(feature_manager, enable_dependency_not_locked_on_try)
{
	feature_manager fm;

	feature_base dep(STATSD, nullptr, {}, fm);
	dep.set_enabled(true);
	feature_base fb0(PROMETHEUS, nullptr, {STATSD}, fm);

	scoped_config<bool> config("prometheus.enabled", true);

	EXPECT_TRUE(test_helper::try_enable(fm, PROMETHEUS));
	EXPECT_TRUE(fb0.get_enabled());
	EXPECT_TRUE(fb0.locked());
	EXPECT_TRUE(dep.get_enabled());
	EXPECT_TRUE(dep.locked());
}

TEST(feature_manager, enable_dependency_not_locked_off_try)
{
	feature_manager fm;

	feature_base dep(STATSD, nullptr, {}, fm);
	dep.set_enabled(false);
	feature_base fb0(PROMETHEUS, nullptr, {STATSD}, fm);

	scoped_config<bool> config("prometheus.enabled", true);

	EXPECT_FALSE(test_helper::try_enable(fm, PROMETHEUS));
}

TEST(feature_manager, enable_dependency_not_locked_off_enableable_try)
{
	feature_manager fm;

	feature_base dep(STATSD, nullptr, {}, fm);
	dep.set_enabled(false);
	scoped_config<bool> config2("statsd.enabled", true);
	feature_base fb0(PROMETHEUS, nullptr, {STATSD}, fm);

	scoped_config<bool> config("prometheus.enabled", true);

	EXPECT_TRUE(test_helper::try_enable(fm, PROMETHEUS));
	EXPECT_TRUE(fb0.get_enabled());
	EXPECT_TRUE(fb0.locked());
	EXPECT_TRUE(dep.get_enabled());
	EXPECT_TRUE(dep.locked());
}

TEST(feature_manager, enable_dependency_chained_try)
{
	feature_manager fm;

	// put a couple at the top of the chain, one locked, one non
	feature_base leaf_dep_locked(STATSD, nullptr, {}, fm);
	leaf_dep_locked.set_enabled(true);
	leaf_dep_locked.set_locked();

	feature_base leaf_dep_unlocked(JMX, nullptr, {}, fm);
	leaf_dep_unlocked.set_enabled(true);

	// put one that calls both of them and has multiple children
	feature_base multi_parent(APP_CHECKS, nullptr, {STATSD, JMX}, fm);
	multi_parent.set_enabled(true);

	// put one that is weakly enableable
	feature_base weak(COINTERFACE, nullptr, {APP_CHECKS}, fm);
	weak.set_enabled(false);
	scoped_config<bool> c1("cointerface_enabled", true);
	scoped_config<bool> c2("cointerface_enabled_opt.weak", true);

	// one that is regularly enableable
	feature_base regular(DRIVER, nullptr, {COINTERFACE, APP_CHECKS}, fm);
	regular.set_enabled(false);
	scoped_config<bool> c3("feature.driver", true);

	feature_base fb0(PROMETHEUS, nullptr, {DRIVER}, fm);
	scoped_config<bool> c4("prometheus.enabled", true);

	EXPECT_TRUE(test_helper::try_enable(fm, PROMETHEUS));
	EXPECT_TRUE(leaf_dep_locked.get_enabled());
	EXPECT_TRUE(leaf_dep_locked.locked());
	EXPECT_TRUE(leaf_dep_unlocked.get_enabled());
	EXPECT_TRUE(leaf_dep_unlocked.locked());
	EXPECT_TRUE(multi_parent.get_enabled());
	EXPECT_TRUE(multi_parent.locked());
	EXPECT_TRUE(weak.get_enabled());
	EXPECT_TRUE(weak.locked());
	EXPECT_TRUE(regular.get_enabled());
	EXPECT_TRUE(regular.locked());
	EXPECT_TRUE(fb0.get_enabled());
	EXPECT_TRUE(fb0.locked());
}

TEST(feature_manager, enable_dependency_chained_fail_try)
{
	feature_manager fm;

	// put a couple at the top of the chain, one locked, one non
	feature_base leaf_dep_locked(STATSD, nullptr, {}, fm);
	leaf_dep_locked.set_enabled(false);
	leaf_dep_locked.set_locked();

	feature_base leaf_dep_unlocked(JMX, nullptr, {}, fm);
	leaf_dep_unlocked.set_enabled(true);

	// put one that calls both of them and has multiple children
	feature_base multi_parent(APP_CHECKS, nullptr, {STATSD, JMX}, fm);
	multi_parent.set_enabled(true);

	// put one that is weakly enableable
	feature_base weak(COINTERFACE, nullptr, {APP_CHECKS}, fm);
	weak.set_enabled(false);
	scoped_config<bool> c1("cointerface_enabled", true);
	scoped_config<bool> c2("cointerface_enabled_opt.weak", true);

	// one that is regularly enableable
	feature_base regular(DRIVER, nullptr, {COINTERFACE, APP_CHECKS}, fm);
	regular.set_enabled(false);
	scoped_config<bool> c3("feature.driver", true);

	feature_base fb0(PROMETHEUS, nullptr, {DRIVER}, fm);
	scoped_config<bool> c4("prometheus.enabled", true);
	scoped_config<bool> c5("prometheus.enabled_opt.weak", true);

	EXPECT_FALSE(test_helper::try_enable(fm, PROMETHEUS));
	EXPECT_FALSE(leaf_dep_locked.get_enabled());
	EXPECT_TRUE(leaf_dep_locked.locked());
	EXPECT_TRUE(leaf_dep_unlocked.get_enabled());
	EXPECT_FALSE(leaf_dep_unlocked.locked());
	EXPECT_TRUE(multi_parent.get_enabled());
	EXPECT_FALSE(multi_parent.locked());
	EXPECT_FALSE(weak.get_enabled());
	EXPECT_FALSE(weak.locked());
	EXPECT_FALSE(regular.get_enabled());
	EXPECT_FALSE(regular.locked());
	EXPECT_FALSE(fb0.get_enabled());
	EXPECT_FALSE(fb0.locked());
}

TEST(feature_manager, disable_try)
{
	feature_manager fm;

	feature_base fb0(PROMETHEUS, nullptr, {}, fm);
	fb0.set_enabled(true);
	scoped_config<bool> config("prometheus.enabled", false);

	EXPECT_TRUE(test_helper::try_disable(fm, PROMETHEUS));
	EXPECT_FALSE(fb0.get_enabled());
	EXPECT_TRUE(fb0.locked());
}

TEST(feature_manager, disable_caller_locked_on_try)
{
	feature_manager fm;

	feature_base fb0(PROMETHEUS, nullptr, {}, fm);
	fb0.set_enabled(true);
	fb0.set_locked();

	scoped_config<bool> config("prometheus.enabled", false);

	EXPECT_FALSE(test_helper::try_disable(fm, PROMETHEUS));
}

TEST(feature_manager, disable_caller_locked_off_try)
{
	feature_manager fm;

	feature_base fb0(PROMETHEUS, nullptr, {}, fm);
	fb0.set_enabled(false);
	fb0.set_locked();

	scoped_config<bool> config("prometheus.enabled", false);

	EXPECT_TRUE(test_helper::try_disable(fm, PROMETHEUS));
	EXPECT_FALSE(fb0.get_enabled());
	EXPECT_TRUE(fb0.locked());
}

TEST(feature_manager, disable_dependency_locked_on_try)
{
	feature_manager fm;

	feature_base dep(STATSD, nullptr, {PROMETHEUS}, fm);
	dep.set_enabled(true);
	dep.set_locked();
	feature_base fb0(PROMETHEUS, nullptr, {}, fm);

	scoped_config<bool> config("prometheus.enabled", false);

	EXPECT_FALSE(test_helper::try_disable(fm, PROMETHEUS));
}

TEST(feature_manager, disable_dependency_locked_off_try)
{
	feature_manager fm;

	feature_base dep(STATSD, nullptr, {PROMETHEUS}, fm);
	dep.set_enabled(false);
	dep.set_locked();
	feature_base fb0(PROMETHEUS, nullptr, {}, fm);

	scoped_config<bool> config("prometheus.enabled", false);

	EXPECT_TRUE(test_helper::try_disable(fm, PROMETHEUS));
	EXPECT_FALSE(fb0.get_enabled());
	EXPECT_TRUE(fb0.locked());
}

TEST(feature_manager, disable_dependency_not_locked_on_try)
{
	feature_manager fm;

	feature_base dep(STATSD, nullptr, {PROMETHEUS}, fm);
	dep.set_enabled(true);
	feature_base fb0(PROMETHEUS, nullptr, {}, fm);

	scoped_config<bool> config("prometheus.enabled", false);

	EXPECT_FALSE(test_helper::try_disable(fm, PROMETHEUS));
}

TEST(feature_manager, disable_dependency_not_locked_off_try)
{
	feature_manager fm;

	feature_base dep(STATSD, nullptr, {PROMETHEUS}, fm);
	dep.set_enabled(false);
	feature_base fb0(PROMETHEUS, nullptr, {}, fm);

	scoped_config<bool> config("prometheus.enabled", false);

	EXPECT_TRUE(test_helper::try_disable(fm, PROMETHEUS));
	EXPECT_FALSE(fb0.get_enabled());
	EXPECT_TRUE(fb0.locked());
	EXPECT_FALSE(dep.get_enabled());
	EXPECT_TRUE(dep.locked());
}

TEST(feature_manager, disable_dependency_not_locked_on_disableable_try)
{
	feature_manager fm;

	feature_base dep(STATSD, nullptr, {PROMETHEUS}, fm);
	dep.set_enabled(true);
	scoped_config<bool> config2("statsd.enabled", false);
	feature_base fb0(PROMETHEUS, nullptr, {}, fm);

	scoped_config<bool> config("prometheus.enabled", false);

	EXPECT_TRUE(test_helper::try_disable(fm, PROMETHEUS));
	EXPECT_FALSE(fb0.get_enabled());
	EXPECT_TRUE(fb0.locked());
	EXPECT_FALSE(dep.get_enabled());
	EXPECT_TRUE(dep.locked());
}

TEST(feature_manager, disable_dependency_chained_try)
{
	feature_manager fm;

	// put a couple at the top of the chain, one locked, one non
	feature_base leaf_dep_locked(STATSD, nullptr, {APP_CHECKS}, fm);
	leaf_dep_locked.set_enabled(false);
	leaf_dep_locked.set_locked();

	feature_base leaf_dep_unlocked(JMX, nullptr, {APP_CHECKS}, fm);
	leaf_dep_unlocked.set_enabled(false);

	// put one that calls both of them and has multiple children
	feature_base multi_parent(APP_CHECKS, nullptr, {COINTERFACE, DRIVER}, fm);
	multi_parent.set_enabled(false);

	// put one that is weakly enableable
	feature_base weak(COINTERFACE, nullptr, {DRIVER}, fm);
	weak.set_enabled(true);
	scoped_config<bool> c1("cointerface_enabled", false);
	scoped_config<bool> c2("cointerface_enabled_opt.weak", true);

	// one that is regularly enableable
	feature_base regular(DRIVER, nullptr, {PROMETHEUS}, fm);
	regular.set_enabled(true);
	scoped_config<bool> c3("feature.driver", false);

	feature_base fb0(PROMETHEUS, nullptr, {}, fm);
	scoped_config<bool> c4("prometheus.enabled", false);

	EXPECT_TRUE(test_helper::try_disable(fm, PROMETHEUS));
	EXPECT_FALSE(leaf_dep_locked.get_enabled());
	EXPECT_TRUE(leaf_dep_locked.locked());
	EXPECT_FALSE(leaf_dep_unlocked.get_enabled());
	EXPECT_TRUE(leaf_dep_unlocked.locked());
	EXPECT_FALSE(multi_parent.get_enabled());
	EXPECT_TRUE(multi_parent.locked());
	EXPECT_FALSE(weak.get_enabled());
	EXPECT_TRUE(weak.locked());
	EXPECT_FALSE(regular.get_enabled());
	EXPECT_TRUE(regular.locked());
	EXPECT_FALSE(fb0.get_enabled());
	EXPECT_TRUE(fb0.locked());
}

TEST(feature_manager, disable_dependency_chained_fail_try)
{
	feature_manager fm;

	// put a couple at the top of the chain, one locked, one non
	feature_base leaf_dep_locked(STATSD, nullptr, {APP_CHECKS}, fm);
	leaf_dep_locked.set_enabled(false);
	leaf_dep_locked.set_locked();

	feature_base leaf_dep_unlocked(JMX, nullptr, {APP_CHECKS}, fm);
	leaf_dep_unlocked.set_enabled(true);

	// put one that calls both of them and has multiple children
	feature_base multi_parent(APP_CHECKS, nullptr, {COINTERFACE, DRIVER}, fm);
	multi_parent.set_enabled(false);

	// put one that is weakly enableable
	feature_base weak(COINTERFACE, nullptr, {DRIVER}, fm);
	weak.set_enabled(true);
	scoped_config<bool> c1("cointerface_enabled", false);
	scoped_config<bool> c2("cointerface_enabled_opt.weak", true);

	// one that is regularly enableable
	feature_base regular(DRIVER, nullptr, {PROMETHEUS}, fm);
	regular.set_enabled(true);
	scoped_config<bool> c3("feature.driver", false);

	feature_base fb0(PROMETHEUS, nullptr, {}, fm);
	scoped_config<bool> c4("prometheus.enabled", false);

	EXPECT_FALSE(test_helper::try_disable(fm, PROMETHEUS));
	EXPECT_FALSE(leaf_dep_locked.get_enabled());
	EXPECT_TRUE(leaf_dep_locked.locked());
	EXPECT_TRUE(leaf_dep_unlocked.get_enabled());
	EXPECT_FALSE(leaf_dep_unlocked.locked());
	EXPECT_FALSE(multi_parent.get_enabled());
	EXPECT_FALSE(multi_parent.locked());
	EXPECT_TRUE(weak.get_enabled());
	EXPECT_FALSE(weak.locked());
	EXPECT_TRUE(regular.get_enabled());
	EXPECT_FALSE(regular.locked());
	EXPECT_FALSE(fb0.get_enabled());
	EXPECT_FALSE(fb0.locked());
}

TEST(feature_manager, force_override_profile)
{
	feature_manager fm;
	dummy_features df(fm);
	test_helpers::scoped_config<std::string> mode("feature.mode", "monitor_light");
	test_helpers::scoped_config<bool> c1("feature.protocol_stats", true);
	test_helpers::scoped_config<bool> c2("feature.protocol_stats_opt.force", true);
	ASSERT_TRUE(fm.initialize());
	// if you look in the dummy features, there are some
	// dependencies specified. Make sure these all get enabled
	// from 14->11. 10 is not a dependency and thus shouldn't be
	EXPECT_TRUE(df.fb14.get_enabled());
	EXPECT_TRUE(df.fb13.get_enabled());
	EXPECT_TRUE(df.fb12.get_enabled());
	EXPECT_TRUE(df.fb11.get_enabled());
	EXPECT_FALSE(df.fb10.get_enabled());
}

TEST(feature_manager, regular_override_profile)
{
	feature_manager fm;
	dummy_features df(fm);
	test_helpers::scoped_config<std::string> mode("feature.mode", "monitor_light");
	test_helpers::scoped_config<bool> c1("feature.full_syscalls", true);
	ASSERT_TRUE(fm.initialize());
	EXPECT_FALSE(df.fb12.get_enabled());
	EXPECT_TRUE(df.fb11.get_enabled());  // the syscall feature
	EXPECT_FALSE(df.fb10.get_enabled());
}

TEST(feature_manager, regular_override_profile_fail)
{
	feature_manager fm;
	dummy_features df(fm);
	test_helpers::scoped_config<std::string> mode("feature.mode", "monitor_light");
	test_helpers::scoped_config<bool> c1("feature.protocol_stats", true);
	ASSERT_FALSE(fm.initialize());
}

TEST(feature_manager, weak_override_profile)
{
	feature_manager fm;
	dummy_features df(fm);
	test_helpers::scoped_config<std::string> mode("feature.mode", "monitor_light");
	test_helpers::scoped_config<bool> c1("feature.full_syscalls", true);
	test_helpers::scoped_config<bool> c2("feature.network_breakdown", true);
	test_helpers::scoped_config<bool> c3("feature.network_breakdown_opt.weak", true);
	ASSERT_TRUE(fm.initialize());
	EXPECT_FALSE(df.fb13.get_enabled());
	EXPECT_TRUE(df.fb12.get_enabled());  // the network_breakdown feature
	EXPECT_TRUE(df.fb11.get_enabled());  // the syscall feature
	EXPECT_FALSE(df.fb10.get_enabled());
}

TEST(feature_manager, weak_override_profile_fail)
{
	feature_manager fm;
	dummy_features df(fm);
	test_helpers::scoped_config<std::string> mode("feature.mode", "monitor_light");
	test_helpers::scoped_config<bool> c2("feature.network_breakdown", true);
	test_helpers::scoped_config<bool> c3("feature.network_breakdown_opt.weak", true);
	ASSERT_TRUE(fm.initialize());
	EXPECT_FALSE(df.fb13.get_enabled());
	EXPECT_FALSE(df.fb12.get_enabled());  // the network_breakdown feature
	EXPECT_FALSE(df.fb11.get_enabled());  // the syscall feature
	EXPECT_FALSE(df.fb10.get_enabled());
}

TEST(feature_manager, two_strong)
{
	feature_manager fm;
	dummy_features df(fm);
	test_helpers::scoped_config<std::string> mode("feature.mode", "monitor_light");
	test_helpers::scoped_config<bool> c1("feature.protocol_stats", true);
	test_helpers::scoped_config<bool> c2("feature.protocol_stats_opt.force", true);
	test_helpers::scoped_config<bool> c3("feature.network_breakdown", true);
	test_helpers::scoped_config<bool> c4("feature.network_breakdown_opt.force", true);
	ASSERT_TRUE(fm.initialize());
	// if you look in the dummy features, there are some
	// dependencies specified. Make sure these all get enabled
	// from 14->11. 10 is not a dependency and thus shouldn't be
	EXPECT_TRUE(df.fb14.get_enabled());
	EXPECT_TRUE(df.fb13.get_enabled());
	EXPECT_TRUE(df.fb12.get_enabled());
	EXPECT_TRUE(df.fb11.get_enabled());
	EXPECT_FALSE(df.fb10.get_enabled());
}

TEST(feature_manager, strong_strong_conflict)
{
	feature_manager fm;
	dummy_features df(fm);
	test_helpers::scoped_config<std::string> mode("feature.mode", "monitor_light");
	test_helpers::scoped_config<bool> c1("feature.protocol_stats", true);
	test_helpers::scoped_config<bool> c2("feature.protocol_stats_opt.force", true);
	test_helpers::scoped_config<bool> c3("feature.network_breakdown", false);
	test_helpers::scoped_config<bool> c4("feature.network_breakdown_opt.force", true);
	ASSERT_FALSE(fm.initialize());
}

TEST(feature_manager, two_regular)
{
	feature_manager fm;
	dummy_features df(fm);
	test_helpers::scoped_config<std::string> mode("feature.mode", "monitor_light");
	test_helpers::scoped_config<bool> c1("feature.full_syscalls", true);
	test_helpers::scoped_config<bool> c3("feature.network_breakdown", true);
	ASSERT_TRUE(fm.initialize());
	EXPECT_TRUE(df.fb12.get_enabled());
	EXPECT_TRUE(df.fb11.get_enabled());  // the syscall feature
	EXPECT_FALSE(df.fb10.get_enabled());
}

TEST(feature_manager, regular_regular_conflict)
{
	feature_manager fm;
	dummy_features df(fm);
	test_helpers::scoped_config<std::string> mode("feature.mode", "monitor_light");
	test_helpers::scoped_config<bool> c1("feature.full_syscalls", false);
	test_helpers::scoped_config<bool> c3("feature.network_breakdown", true);
	ASSERT_FALSE(fm.initialize());
}

TEST(feature_manager, regular_on_strong_conflict)
{
	feature_manager fm;
	dummy_features df(fm);
	test_helpers::scoped_config<std::string> mode("feature.mode", "monitor_light");
	test_helpers::scoped_config<bool> c1("feature.full_syscalls", false);
	test_helpers::scoped_config<bool> c3("feature.full_syscalls_opt.force", true);
	test_helpers::scoped_config<bool> c2("feature.network_breakdown", true);
	ASSERT_FALSE(fm.initialize());
}

TEST(feature_manager, strong_on_regular_conflict)
{
	feature_manager fm;
	dummy_features df(fm);
	test_helpers::scoped_config<std::string> mode("feature.mode", "monitor_light");
	test_helpers::scoped_config<bool> c1("feature.full_syscalls", false);
	test_helpers::scoped_config<bool> c2("feature.network_breakdown", true);
	test_helpers::scoped_config<bool> c3("feature.network_breakdown_opt.force", true);
	ASSERT_FALSE(fm.initialize());
}

TEST(feature_manager, two_weak)
{
	feature_manager fm;
	dummy_features df(fm);
	test_helpers::scoped_config<std::string> mode("feature.mode", "monitor_light");
	test_helpers::scoped_config<bool> c1("feature.full_syscalls", true);
	test_helpers::scoped_config<bool> c4("feature.full_syscalls_opt.weak", true);
	test_helpers::scoped_config<bool> c2("feature.network_breakdown", true);
	test_helpers::scoped_config<bool> c3("feature.network_breakdown_opt.weak", true);
	ASSERT_TRUE(fm.initialize());
	EXPECT_TRUE(df.fb12.get_enabled());
	EXPECT_TRUE(df.fb11.get_enabled());  // the syscall feature
	EXPECT_FALSE(df.fb10.get_enabled());
}

TEST(feature_manager, weak_on_strong_conflict)
{
	feature_manager fm;
	dummy_features df(fm);
	test_helpers::scoped_config<std::string> mode("feature.mode", "monitor_light");
	test_helpers::scoped_config<bool> c1("feature.full_syscalls", false);
	test_helpers::scoped_config<bool> c3("feature.full_syscalls_opt.force", true);
	test_helpers::scoped_config<bool> c2("feature.network_breakdown", true);
	test_helpers::scoped_config<bool> c4("feature.network_breakdown_opt.weak", true);
	ASSERT_TRUE(fm.initialize());
	EXPECT_FALSE(df.fb12.get_enabled());
	EXPECT_FALSE(df.fb11.get_enabled());  // the syscall feature
	EXPECT_FALSE(df.fb10.get_enabled());
}

TEST(feature_manager, strong_on_weak_conflict)
{
	feature_manager fm;
	dummy_features df(fm);
	test_helpers::scoped_config<std::string> mode("feature.mode", "monitor_light");
	test_helpers::scoped_config<bool> c1("feature.full_syscalls", false);
	test_helpers::scoped_config<bool> c4("feature.full_syscalls_opt.weak", true);
	test_helpers::scoped_config<bool> c2("feature.network_breakdown", true);
	test_helpers::scoped_config<bool> c3("feature.network_breakdown_opt.force", true);
	ASSERT_TRUE(fm.initialize());
	EXPECT_TRUE(df.fb12.get_enabled());
	EXPECT_TRUE(df.fb11.get_enabled());  // the syscall feature
	EXPECT_FALSE(df.fb10.get_enabled());
}

TEST(feature_manager, weak_on_regular_conflict)
{
	feature_manager fm;
	dummy_features df(fm);
	test_helpers::scoped_config<std::string> mode("feature.mode", "monitor_light");
	test_helpers::scoped_config<bool> c1("feature.full_syscalls", false);
	test_helpers::scoped_config<bool> c2("feature.network_breakdown", true);
	test_helpers::scoped_config<bool> c3("feature.network_breakdown_opt.weak", true);
	ASSERT_TRUE(fm.initialize());
	EXPECT_FALSE(df.fb12.get_enabled());
	EXPECT_FALSE(df.fb11.get_enabled());  // the syscall feature
	EXPECT_FALSE(df.fb10.get_enabled());
}

TEST(feature_manager, regular_on_weak_conflict)
{
	feature_manager fm;
	dummy_features df(fm);
	// use essentials since we need something enabled in the config the weak one
	// can fail to enable
	test_helpers::scoped_config<std::string> mode("feature.mode", "essentials");
	test_helpers::scoped_config<bool> c1("feature.full_syscalls", false);
	test_helpers::scoped_config<bool> c3("feature.full_syscalls_opt.weak", true);
	test_helpers::scoped_config<bool> c2("feature.network_breakdown", true);
	ASSERT_TRUE(fm.initialize());
	EXPECT_TRUE(df.fb12.get_enabled());
	EXPECT_TRUE(df.fb11.get_enabled());  // the syscall feature
	EXPECT_FALSE(df.fb10.get_enabled());
}

TEST(feature_manager, weak_weak_conflict)
{
	feature_manager fm;
	dummy_features df(fm);
	test_helpers::scoped_config<std::string> mode("feature.mode", "essentials");
	test_helpers::scoped_config<bool> c1("feature.full_syscalls", false);
	test_helpers::scoped_config<bool> c2("feature.full_syscalls_opt.weak", true);
	test_helpers::scoped_config<bool> c3("feature.network_breakdown", true);
	test_helpers::scoped_config<bool> c4("feature.network_breakdown_opt.weak", true);
	ASSERT_TRUE(fm.initialize());  // The success of this will ultimately depend on the
	                               // ordering of the features in the map. Making
	                               // it transparently predictable would be a PITA
	                               // Here, syscalls comes first, so it wins, and
	                               // disables, and the network breakdown fails
	EXPECT_FALSE(df.fb12.get_enabled());
	EXPECT_FALSE(df.fb11.get_enabled());  // the syscall feature
	EXPECT_FALSE(df.fb10.get_enabled());
}

TEST(feature_manager, reinitialize)
{
	// we don't expect this to happen in the normal course of operation,
	// but because our UTs are a giant blob, we need to be able to reinitialize
	// the feature manager with different values. Check to make sure that works.
	test_helpers::scoped_config<std::string> mode("feature.mode", "monitor_light");
	test_helpers::scoped_config<bool> c1("feature.network_breakdown_opt.force", true);

	// why do we twiddle this 3 times? It's a bit of an implementation detail, where
	// it might not fail unless we twiddle it back and forth a couple times
	// 1) feature gets enabled and locked
	// 2) in failure case, feature is still locked, but gets disabled by the profile,
	//    thus the test case succeeds, because the value is still false
	// 3) now the config is unable to enable, since it's locked and set false by profile
	{
		test_helpers::scoped_config<bool> c3("feature.network_breakdown", true);
		ASSERT_TRUE(feature_manager::instance().initialize());
	}
	{
		test_helpers::scoped_config<bool> c3("feature.network_breakdown", false);
		ASSERT_TRUE(feature_manager::instance().initialize());
	}
	{
		test_helpers::scoped_config<bool> c3("feature.network_breakdown", true);
		ASSERT_TRUE(feature_manager::instance().initialize());
	}
}

TEST(feature_manager, config)
{
	// we want to double check that the fancy config business works as we think it should
	const std::string config = R"EOF(
prometheus:
  enabled: true
  enabled_opt:
    force: true

app_checks_enabled: false
app_checks_enabled_opt:
  weak: true
)EOF";
	test_helpers::scoped_configuration enabled_config(config);

	EXPECT_TRUE(
	    configuration_manager::instance().get_config<bool>("prometheus.enabled")->get_value());
	EXPECT_TRUE(configuration_manager::instance()
	                .get_config<bool>("prometheus.enabled_opt.force")
	                ->get_value());
	EXPECT_FALSE(
	    configuration_manager::instance().get_config<bool>("app_checks_enabled")->get_value());
	EXPECT_TRUE(configuration_manager::instance()
	                .get_config<bool>("app_checks_enabled_opt.weak")
	                ->get_value());
}

TEST(feature_manager, invalid_mode)
{
	feature_manager fm;
	test_helpers::scoped_config<std::string> mode("feature.mode", "foobar");
	dummy_features df(fm);
	{
		test_helpers::scoped_config<bool> pom("prometheus.enabled", true);
		test_helpers::scoped_config<bool> sd("statsd.enabled", false);
		EXPECT_TRUE(fm.initialize());

		EXPECT_TRUE(fm.get_enabled(PROMETHEUS));
		EXPECT_FALSE(fm.get_enabled(STATSD));
	}
	{
		test_helpers::scoped_config<bool> pom("prometheus.enabled", false);
		test_helpers::scoped_config<bool> sd("statsd.enabled", true);
		EXPECT_TRUE(fm.initialize());

		EXPECT_FALSE(fm.get_enabled(PROMETHEUS));
		EXPECT_TRUE(fm.get_enabled(STATSD));
	}
}

TEST(feature_manager, monitor_mode)
{
	feature_manager fm;
	dummy_features df(fm, true);
	test_helpers::scoped_config<std::string> mode("feature.mode", "monitor");
	EXPECT_TRUE(fm.initialize());

	EXPECT_FALSE(fm.get_enabled(PROMETHEUS));
	EXPECT_TRUE(fm.get_enabled(STATSD));
	EXPECT_EQ(
	    configuration_manager::instance().get_config<uint32_t>("http.url_table_size")->get_value(),
	    0);
}

TEST(feature_manager, monitor_light_mode)
{
	feature_manager fm;
	dummy_features df(fm);
	test_helpers::scoped_config<std::string> mode("feature.mode", "monitor_light");
	EXPECT_TRUE(fm.initialize());

	EXPECT_FALSE(fm.get_enabled(PROMETHEUS));
	EXPECT_FALSE(fm.get_enabled(STATSD));
	EXPECT_EQ(
	    configuration_manager::instance().get_config<uint32_t>("http.url_table_size")->get_value(),
	    0);
}

TEST(feature_manager, essentials_mode)
{
	feature_manager fm;
	dummy_features df(fm);
	test_helpers::scoped_config<std::string> mode("feature.mode", "essentials");
	EXPECT_TRUE(fm.initialize());

	EXPECT_FALSE(fm.get_enabled(PROMETHEUS));
	EXPECT_TRUE(fm.get_enabled(STATSD));
	EXPECT_EQ(
	    configuration_manager::instance().get_config<uint32_t>("http.url_table_size")->get_value(),
	    0);
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

TEST(feature_manager, config_override)
{
	feature_manager fm;
	dummy_features df(fm, true);
	test_helpers::scoped_config<uint32_t> urls("http.url_table_size", 1);
	test_helpers::scoped_config<std::string> mode("feature.mode", "monitor");
	EXPECT_TRUE(fm.initialize());
	EXPECT_EQ(
	    configuration_manager::instance().get_config<uint32_t>("http.url_table_size")->get_value(),
	    1);
	draiosproto::feature_status proto;
	fm.to_protobuf(proto);
	EXPECT_TRUE(proto.custom_config());
}

TEST(feature_manager, to_protobuf)
{
	feature_manager fm;
	dummy_features df(fm, true);
	{
		test_helpers::scoped_config<std::string> mode("feature.mode", "monitor_light");
		EXPECT_TRUE(fm.initialize());
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
		EXPECT_FALSE(proto.network_breakdown_enabled());
		EXPECT_FALSE(proto.file_breakdown_enabled());
		EXPECT_FALSE(proto.protocol_stats_enabled());
		EXPECT_FALSE(proto.http_stats_enabled());
		EXPECT_FALSE(proto.mysql_stats_enabled());
		EXPECT_FALSE(proto.postgres_stats_enabled());
		EXPECT_FALSE(proto.mongodb_stats_enabled());
		EXPECT_FALSE(proto.custom_config());
		EXPECT_TRUE(proto.monitor_enabled());
	}
	{
		test_helpers::scoped_config<std::string> mode("feature.mode", "none");
		EXPECT_TRUE(fm.initialize());
		draiosproto::feature_status proto;
		fm.to_protobuf(proto);
		EXPECT_EQ(proto.mode(), draiosproto::agent_mode::legacy);
	}
	{
		test_helpers::scoped_config<std::string> mode("feature.mode", "monitor");
		EXPECT_TRUE(fm.initialize());
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
		EXPECT_TRUE(proto.network_breakdown_enabled());
		EXPECT_FALSE(proto.file_breakdown_enabled());
		EXPECT_TRUE(proto.protocol_stats_enabled());
		EXPECT_TRUE(proto.http_stats_enabled());
		EXPECT_FALSE(proto.mysql_stats_enabled());
		EXPECT_FALSE(proto.postgres_stats_enabled());
		EXPECT_FALSE(proto.mongodb_stats_enabled());
		EXPECT_FALSE(proto.custom_config());
		EXPECT_TRUE(proto.monitor_enabled());
	}
	{
		test_helpers::scoped_config<std::string> mode("feature.mode", "essentials");
		EXPECT_TRUE(fm.initialize());
		draiosproto::feature_status proto;
		fm.to_protobuf(proto);
		EXPECT_EQ(proto.mode(), draiosproto::agent_mode::essentials);
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
		EXPECT_FALSE(proto.network_breakdown_enabled());
		EXPECT_FALSE(proto.file_breakdown_enabled());
		EXPECT_FALSE(proto.protocol_stats_enabled());
		EXPECT_FALSE(proto.http_stats_enabled());
		EXPECT_FALSE(proto.mysql_stats_enabled());
		EXPECT_FALSE(proto.postgres_stats_enabled());
		EXPECT_FALSE(proto.mongodb_stats_enabled());
		EXPECT_FALSE(proto.custom_config());
		EXPECT_TRUE(proto.monitor_enabled());
	}
	{
		test_helpers::scoped_config<std::string> mode("feature.mode", "troubleshooting");
		EXPECT_TRUE(fm.initialize());
		draiosproto::feature_status proto;
		fm.to_protobuf(proto);
		EXPECT_EQ(proto.mode(), draiosproto::agent_mode::troubleshooting);
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
		EXPECT_TRUE(proto.network_breakdown_enabled());
		EXPECT_TRUE(proto.file_breakdown_enabled());
		EXPECT_TRUE(proto.protocol_stats_enabled());
		EXPECT_TRUE(proto.http_stats_enabled());
		EXPECT_TRUE(proto.mysql_stats_enabled());
		EXPECT_TRUE(proto.postgres_stats_enabled());
		EXPECT_TRUE(proto.mongodb_stats_enabled());
		EXPECT_FALSE(proto.custom_config());
		EXPECT_TRUE(proto.monitor_enabled());
	}
	{
		test_helpers::scoped_config<std::string> mode("feature.mode", "secure");
		EXPECT_TRUE(fm.initialize());
		draiosproto::feature_status proto;
		fm.to_protobuf(proto);
		EXPECT_EQ(proto.mode(), draiosproto::agent_mode::secure);
		EXPECT_FALSE(proto.prometheus_enabled());
		EXPECT_TRUE(proto.statsd_enabled());
		EXPECT_FALSE(proto.jmx_enabled());
		EXPECT_FALSE(proto.app_checks_enabled());
		EXPECT_TRUE(proto.cointerface_enabled());
		EXPECT_TRUE(proto.driver_enabled());
		EXPECT_FALSE(proto.secure_enabled());
		EXPECT_FALSE(proto.commandline_capture_enabled());
		EXPECT_FALSE(proto.baseliner_enabled());
		EXPECT_FALSE(proto.memdump_enabled());
		EXPECT_FALSE(proto.secure_audit_enabled());
		EXPECT_TRUE(proto.full_syscalls_enabled());
		EXPECT_FALSE(proto.network_breakdown_enabled());
		EXPECT_FALSE(proto.file_breakdown_enabled());
		EXPECT_FALSE(proto.protocol_stats_enabled());
		EXPECT_FALSE(proto.http_stats_enabled());
		EXPECT_FALSE(proto.mysql_stats_enabled());
		EXPECT_FALSE(proto.postgres_stats_enabled());
		EXPECT_FALSE(proto.mongodb_stats_enabled());
		EXPECT_FALSE(proto.custom_config());
		EXPECT_FALSE(proto.monitor_enabled());
	}

}
