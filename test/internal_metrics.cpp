#include <gtest.h>
#include <string>
#include <iostream>
#include "Poco/Message.h"
#include "sys_call_test.h"
#include "internal_metrics.h"
#include "draios.pb.h"

using namespace Poco;
using Poco::Message;

const char* allstr();
const char* logstr();

TEST(internal_metrics, metrics)
{
	internal_metrics im;
	ASSERT_EQ(0u, im.logs());

	ASSERT_EQ(-1, im.get_process());
	ASSERT_EQ(-1, im.get_thread());
	ASSERT_EQ(-1, im.get_container());
	ASSERT_EQ(-1, im.get_javaproc());
	ASSERT_EQ(-1, im.get_appcheck());
	ASSERT_FALSE(im.get_mesos_autodetect());
	ASSERT_FALSE(im.get_mesos_detected());
	ASSERT_EQ(-1, im.get_fp());
	ASSERT_EQ(-1, im.get_fl());
	ASSERT_EQ(-1, im.get_sr());

	ASSERT_EQ(-1, im.get_n_evts());
	ASSERT_EQ(-1, im.get_n_drops());
	ASSERT_EQ(-1, im.get_n_drops_buffer());
	ASSERT_EQ(-1, im.get_n_preemptions());

	ASSERT_EQ(-1, im.get_agent_cpu());
	ASSERT_EQ(-1, im.get_agent_memory());
	ASSERT_EQ(-1, im.get_java_cpu());
	ASSERT_EQ(-1, im.get_java_memory());
	ASSERT_EQ(-1, im.get_appcheck_cpu());
	ASSERT_EQ(-1, im.get_appcheck_memory());
	ASSERT_EQ(-1, im.get_mountedfs_reader_cpu());
	ASSERT_EQ(-1, im.get_mountedfs_reader_memory());
	ASSERT_EQ(-1, im.get_statsite_forwarder_cpu());
	ASSERT_EQ(-1, im.get_statsite_forwarder_memory());
	ASSERT_EQ(-1, im.get_cointerface_cpu());
	ASSERT_EQ(-1, im.get_cointerface_memory());

	Message msg;
	msg.setPriority(Message::PRIO_FATAL);
	im.notify(msg.getPriority());
	msg.setPriority(Message::PRIO_CRITICAL);
	im.notify(msg.getPriority());
	msg.setPriority(Message::PRIO_ERROR);
	im.notify(msg.getPriority());
	msg.setPriority(Message::PRIO_WARNING);
	im.notify(msg.getPriority());
	msg.setPriority(Message::PRIO_NOTICE);
	im.notify(msg.getPriority());
	msg.setPriority(Message::PRIO_INFORMATION);
	im.notify(msg.getPriority());
	msg.setPriority(Message::PRIO_DEBUG);
	im.notify(msg.getPriority());
	msg.setPriority(Message::PRIO_TRACE);
	im.notify(msg.getPriority());
	EXPECT_EQ(4u, im.logs());

	draiosproto::statsd_info info;
	ASSERT_TRUE(im.send_all(&info));
	EXPECT_EQ(info.DebugString(), logstr());
	EXPECT_EQ(0u, im.logs());

	im.set_process(999);
	im.set_thread(999);
	im.set_container(999);
	im.set_javaproc(999);
	im.set_appcheck(999);
	im.set_mesos_autodetect(true);
	im.set_mesos_detected(true);
	im.set_fp(999);
	im.set_fl(999);
	im.set_sr(999);

	im.set_n_evts(999);
	im.set_n_drops(998);
	im.set_n_drops_buffer(997);
	im.set_n_preemptions(996);

	EXPECT_EQ(999, im.get_process());
	EXPECT_EQ(999, im.get_thread());
	EXPECT_EQ(999, im.get_container());
	EXPECT_EQ(999, im.get_javaproc());
	EXPECT_EQ(999, im.get_appcheck());

	EXPECT_TRUE(im.get_mesos_autodetect());
	EXPECT_TRUE(im.get_mesos_detected());
	EXPECT_EQ(999, im.get_fp());
	EXPECT_EQ(999, im.get_fl());
	EXPECT_EQ(999, im.get_sr());

	EXPECT_EQ(999, im.get_n_evts());
	EXPECT_EQ(998, im.get_n_drops());
	EXPECT_EQ(997, im.get_n_drops_buffer());
	EXPECT_EQ(996, im.get_n_preemptions());

	im.set_agent_cpu(999);
	im.set_agent_memory(999);
	im.set_java_cpu(999);
	im.set_java_memory(999);
	im.set_appcheck_cpu(999);
	im.set_appcheck_memory(999);
	im.set_mountedfs_reader_cpu(999);
	im.set_mountedfs_reader_memory(999);
	im.set_statsite_forwarder_cpu(999);
	im.set_statsite_forwarder_memory(999);
	im.set_cointerface_cpu(999);
	im.set_cointerface_memory(999);

	EXPECT_EQ(999, im.get_agent_cpu());
	EXPECT_EQ(999, im.get_agent_memory());
	EXPECT_EQ(999, im.get_java_cpu());
	EXPECT_EQ(999, im.get_java_memory());
	EXPECT_EQ(999, im.get_appcheck_cpu());
	EXPECT_EQ(999, im.get_appcheck_memory());
	EXPECT_EQ(999, im.get_mountedfs_reader_cpu());
	EXPECT_EQ(999, im.get_mountedfs_reader_memory());
	EXPECT_EQ(999, im.get_statsite_forwarder_cpu());
	EXPECT_EQ(999, im.get_statsite_forwarder_memory());
	EXPECT_EQ(999, im.get_cointerface_cpu());
	EXPECT_EQ(999, im.get_cointerface_memory());

	info.Clear();
	ASSERT_TRUE(im.send_all(&info));
	EXPECT_EQ(info.DebugString(), allstr());
	EXPECT_EQ(0u, im.logs());

	// gauges remain intact after send
	EXPECT_EQ(999, im.get_process());
	EXPECT_EQ(999, im.get_thread());
	EXPECT_EQ(999, im.get_container());
	EXPECT_EQ(999, im.get_javaproc());
	EXPECT_EQ(999, im.get_appcheck());
	EXPECT_TRUE(im.get_mesos_autodetect());
	EXPECT_TRUE(im.get_mesos_detected());
	EXPECT_EQ(999, im.get_fp());
	EXPECT_EQ(999, im.get_fl());
	EXPECT_EQ(999, im.get_sr());

	EXPECT_EQ(999, im.get_n_evts());
	EXPECT_EQ(998, im.get_n_drops());
	EXPECT_EQ(997, im.get_n_drops_buffer());
	EXPECT_EQ(996, im.get_n_preemptions());

	EXPECT_EQ(999, im.get_agent_cpu());
	EXPECT_EQ(999, im.get_agent_memory());
	EXPECT_EQ(999, im.get_java_cpu());
	EXPECT_EQ(999, im.get_java_memory());
	EXPECT_EQ(999, im.get_appcheck_cpu());
	EXPECT_EQ(999, im.get_appcheck_memory());
	EXPECT_EQ(999, im.get_mountedfs_reader_cpu());
	EXPECT_EQ(999, im.get_mountedfs_reader_memory());
	EXPECT_EQ(999, im.get_statsite_forwarder_cpu());
	EXPECT_EQ(999, im.get_statsite_forwarder_memory());
	EXPECT_EQ(999, im.get_cointerface_cpu());
	EXPECT_EQ(999, im.get_cointerface_memory());

	info.Clear();
	draiosproto::statsd_metric* metric = im.write_metric(&info, "xyz", draiosproto::STATSD_GAUGE,  -1);
	EXPECT_EQ(nullptr, metric);
	metric = im.write_metric(&info, "xyz", draiosproto::STATSD_GAUGE,  1);
	ASSERT_FALSE(nullptr == metric);
	const char* mstr = "name: \"xyz\"\ntype: STATSD_GAUGE\nvalue: 1\n";
	EXPECT_EQ(metric->DebugString(), mstr);
}

const char* logstr()
{
	return
	"statsd_metrics {\n"
	"  name: \"dragent.log.err\"\n"
	"  type: STATSD_COUNT\n"
	"  value: 1\n"
	"}\n"
	"statsd_metrics {\n"
	"  name: \"dragent.log.warn\"\n"
	"  type: STATSD_COUNT\n"
	"  value: 1\n"
	"}\n"
	"statsd_metrics {\n"
	"  name: \"dragent.log.info\"\n"
	"  type: STATSD_COUNT\n"
	"  value: 1\n"
	"}\n"
	"statsd_metrics {\n"
	"  name: \"dragent.log.debug\"\n"
	"  type: STATSD_COUNT\n"
	"  value: 1\n"
	"}\n"
	"statsd_metrics {\n"
	"  name: \"dragent.analyzer.mesos.autodetect\"\n"
	"  type: STATSD_GAUGE\n"
	"  value: 0\n"
	"}\n"
	"statsd_metrics {\n"
	"  name: \"dragent.analyzer.mesos.detected\"\n"
	"  type: STATSD_GAUGE\n"
	"  value: 0\n"
	"}\n";
}

const char* allstr()
{
	return
	"statsd_metrics {\n"
	"  name: \"dragent.log.err\"\n"
	"  type: STATSD_COUNT\n"
	"  value: 0\n"
	"}\n"
	"statsd_metrics {\n"
	"  name: \"dragent.log.warn\"\n"
	"  type: STATSD_COUNT\n"
	"  value: 0\n"
	"}\n"
	"statsd_metrics {\n"
	"  name: \"dragent.log.info\"\n"
	"  type: STATSD_COUNT\n"
	"  value: 0\n"
	"}\n"
	"statsd_metrics {\n"
	"  name: \"dragent.log.debug\"\n"
	"  type: STATSD_COUNT\n"
	"  value: 0\n"
	"}\n"
	"statsd_metrics {\n"
	"  name: \"dragent.analyzer.processes\"\n"
	"  type: STATSD_GAUGE\n"
	"  value: 999\n"
	"}\n"
	"statsd_metrics {\n"
	"  name: \"dragent.analyzer.threads\"\n"
	"  type: STATSD_GAUGE\n"
	"  value: 999\n"
	"}\n"
	"statsd_metrics {\n"
	"  name: \"dragent.analyzer.containers\"\n"
	"  type: STATSD_GAUGE\n"
	"  value: 999\n"
	"}\n"
	"statsd_metrics {\n"
	"  name: \"dragent.analyzer.javaprocs\"\n"
	"  type: STATSD_GAUGE\n"
	"  value: 999\n"
	"}\n"
	"statsd_metrics {\n"
	"  name: \"dragent.analyzer.appchecks\"\n"
	"  type: STATSD_GAUGE\n"
	"  value: 999\n"
	"}\n"
	"statsd_metrics {\n"
	"  name: \"dragent.analyzer.mesos.autodetect\"\n"
	"  type: STATSD_GAUGE\n"
	"  value: 1\n"
	"}\n"
	"statsd_metrics {\n"
	"  name: \"dragent.analyzer.mesos.detected\"\n"
	"  type: STATSD_GAUGE\n"
	"  value: 1\n"
	"}\n"
	"statsd_metrics {\n"
	"  name: \"dragent.analyzer.fp.pct100\"\n"
	"  type: STATSD_GAUGE\n"
	"  value: 999\n"
	"}\n"
	"statsd_metrics {\n"
	"  name: \"dragent.analyzer.fl.ms\"\n"
	"  type: STATSD_GAUGE\n"
	"  value: 999\n"
	"}\n"
	"statsd_metrics {\n"
	"  name: \"dragent.analyzer.sr\"\n"
	"  type: STATSD_GAUGE\n"
	"  value: 999\n"
	"}\n"
	"statsd_metrics {\n"
	"  name: \"dragent.analyzer.n_evts\"\n"
	"  type: STATSD_GAUGE\n"
	"  value: 999\n"
	"}\n"
	"statsd_metrics {\n"
	"  name: \"dragent.analyzer.n_drops\"\n"
	"  type: STATSD_GAUGE\n"
	"  value: 998\n"
	"}\n"
	"statsd_metrics {\n"
	"  name: \"dragent.analyzer.n_drops_buffer\"\n"
	"  type: STATSD_GAUGE\n"
	"  value: 997\n"
	"}\n"
	"statsd_metrics {\n"
	"  name: \"dragent.analyzer.n_preemptions\"\n"
	"  type: STATSD_GAUGE\n"
	"  value: 996\n"
	"}\n"
	"statsd_metrics {\n"
	"  name: \"dragent.subproc.agent.cpu.pct100\"\n"
	"  type: STATSD_GAUGE\n"
	"  value: 999\n"
	"}\n"
	"statsd_metrics {\n"
	"  name: \"dragent.subproc.agent.memory.kb\"\n"
	"  type: STATSD_GAUGE\n"
	"  value: 999\n"
	"}\n"
	"statsd_metrics {\n"
	"  name: \"dragent.subproc.java.cpu.pct100\"\n"
	"  type: STATSD_GAUGE\n"
	"  value: 999\n"
	"}\n"
	"statsd_metrics {\n"
	"  name: \"dragent.subproc.java.memory.kb\"\n"
	"  type: STATSD_GAUGE\n"
	"  value: 999\n"
	"}\n"
	"statsd_metrics {\n"
	"  name: \"dragent.subproc.appcheck.cpu.pct100\"\n"
	"  type: STATSD_GAUGE\n"
	"  value: 999\n"
	"}\n"
	"statsd_metrics {\n"
	"  name: \"dragent.subproc.appcheck.memory.kb\"\n"
	"  type: STATSD_GAUGE\n"
	"  value: 999\n"
	"}\n"
	"statsd_metrics {\n"
	"  name: \"dragent.subproc.mountedfs.reader.cpu.pct100\"\n"
	"  type: STATSD_GAUGE\n"
	"  value: 999\n"
	"}\n"
	"statsd_metrics {\n"
	"  name: \"dragent.subproc.mountedfs.reader.memory.kb\"\n"
	"  type: STATSD_GAUGE\n"
	"  value: 999\n"
	"}\n"
	"statsd_metrics {\n"
	"  name: \"dragent.subproc.cointerface.cpu.pct100\"\n"
	"  type: STATSD_GAUGE\n"
	"  value: 999\n"
	"}\n"
	"statsd_metrics {\n"
	"  name: \"dragent.subproc.cointerface.memory.kb\"\n"
	"  type: STATSD_GAUGE\n"
	"  value: 999\n"
	"}\n"
	"statsd_metrics {\n"
	"  name: \"dragent.subproc.statsite.forwarder.cpu.pct100\"\n"
	"  type: STATSD_GAUGE\n"
	"  value: 999\n"
	"}\n"
	"statsd_metrics {\n"
	"  name: \"dragent.subproc.statsite.forwarder.memory.kb\"\n"
	"  type: STATSD_GAUGE\n"
	"  value: 999\n"
	"}\n";
}
