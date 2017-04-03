#include <gtest.h>
#include <string>
#include <map>
#include <unordered_map>
#include "sinsp.h"
#include "sinsp_int.h"
#include "utils.h"
#include "user_event.h"

/*
events:
  kubernetes:
    namespace: [all] | [ADDED, MODIFIED, DELETED, ERROR]
    node: [all] | [ADDED, MODIFIED, DELETED, ERROR]
    pod: [all] | [ADDED, MODIFIED, DELETED, ERROR]
    service: [all] | [ADDED, MODIFIED, DELETED, ERROR]
    replicationController: [all] | [ADDED, MODIFIED, DELETED, ERROR]
  docker:
    container: [all] | [attach, commit, copy, create, destroy, die, exec_create, exec_start, export, kill, oom, pause, rename, resize, restart, start, stop, top, unpause, update]
    image: [all] | [delete, import, pull, push, tag, untag]
    volume: [all] | [create, mount, unmount, destroy]
    network: [all] | [create, connect, disconnect, destroy]
*/

TEST(user_event, meta_t)
{
	//event_t::filter_t{ { "pod", {"all"} }, /*{ "node", {"all"} }*/ }
	user_event_meta_t evt;
	EXPECT_FALSE(evt.is_kind("pod"));
	EXPECT_FALSE(evt.is_kind("POD"));
	EXPECT_FALSE(evt.is_kind("node"));
	EXPECT_FALSE(evt.is_kind("NODE"));
	EXPECT_FALSE(evt.has_type("added"));
	EXPECT_FALSE(evt.has_type("ADDED"));
	EXPECT_FALSE(evt.has_type("MODIFIED"));
	EXPECT_FALSE(evt.has_type("DELETED"));
	EXPECT_FALSE(evt.has_type("ERROR"));

	user_event_meta_t evt0("pod", {"ADDED"});
	EXPECT_TRUE(evt0.is_kind("pod"));
	EXPECT_TRUE(evt0.is_kind("POD"));
	EXPECT_FALSE(evt0.is_kind("node"));
	EXPECT_FALSE(evt0.is_kind("NODE"));
	EXPECT_TRUE(evt0.has_type("added"));
	EXPECT_TRUE(evt0.has_type("ADDED"));
	EXPECT_FALSE(evt0.has_type("MODIFIED"));
	EXPECT_FALSE(evt0.has_type("DELETED"));
	EXPECT_FALSE(evt0.has_type("ERROR"));

	user_event_meta_t evt1("nODe", {"ADDED", "ERROR"});
	EXPECT_FALSE(evt1.is_kind("pod"));
	EXPECT_FALSE(evt1.is_kind("POD"));
	EXPECT_TRUE(evt1.is_kind("node"));
	EXPECT_TRUE(evt1.is_kind("NODE"));
	EXPECT_TRUE(evt1.has_type("added"));
	EXPECT_TRUE(evt1.has_type("ADDED"));
	EXPECT_FALSE(evt1.has_type("MODIFIED"));
	EXPECT_FALSE(evt1.has_type("DELETED"));
	EXPECT_TRUE(evt1.has_type("ERROR"));

	user_event_meta_t evt2("pod", {"all"});
	EXPECT_TRUE(evt2.is_kind("pod"));
	EXPECT_TRUE(evt2.is_kind("POD"));
	EXPECT_FALSE(evt2.is_kind("node"));
	EXPECT_FALSE(evt2.is_kind("NODE"));
	EXPECT_TRUE(evt2.has_type("added"));
	EXPECT_TRUE(evt2.has_type("ADDED"));
	EXPECT_TRUE(evt2.has_type("MODIFIED"));
	EXPECT_TRUE(evt2.has_type("DELETED"));
	EXPECT_TRUE(evt2.has_type("ERROR"));
	EXPECT_TRUE(evt2.has_type("blah"));
}

TEST(user_event, filter_t)
{
	user_event_meta_t evt_all("all", {"all"});
	user_event_meta_t evt_none("none", {"none"});
	user_event_meta_t evt("pod", {"ADDED"});
	user_event_filter_t flt({evt});
	EXPECT_TRUE(flt.allows(evt));
	EXPECT_FALSE(flt.allows(evt_all));
	flt.add(evt_all);
	EXPECT_TRUE(flt.allows(evt));
	EXPECT_TRUE(flt.allows(user_event_meta_t("node", {"MODIFIED"})));
	EXPECT_TRUE(flt.allows(evt_all));
	EXPECT_TRUE(flt.allows_all("pod"));
	EXPECT_TRUE(flt.allows_all("node"));
	flt.clear();
	EXPECT_FALSE(flt.allows(evt));
	EXPECT_FALSE(flt.allows(evt_all));
	EXPECT_FALSE(flt.allows_all("pod"));
	EXPECT_FALSE(flt.allows_all("node"));

	user_event_meta_t evt0("nODe", {"ADDED", "ERROR"});
	flt.add(evt0);
	EXPECT_FALSE(flt.allows(evt));
	EXPECT_TRUE(flt.allows(evt0));
	EXPECT_TRUE(flt.allows(user_event_meta_t("nODe", {"ADDED"})));
	EXPECT_TRUE(flt.allows(user_event_meta_t("node", {"AddeD"})));
	EXPECT_TRUE(flt.allows(user_event_meta_t("node", {"eRRor"})));
	EXPECT_FALSE(flt.allows(user_event_meta_t("node", {"MODIFIED"})));
	EXPECT_FALSE(flt.allows(user_event_meta_t("pod", {"ADDED"})));
	flt.add(evt);
	EXPECT_TRUE(flt.allows(evt));
	EXPECT_TRUE(flt.allows(evt0));
	EXPECT_TRUE(flt.allows(user_event_meta_t("nODe", {"ADDED"})));
	EXPECT_TRUE(flt.allows(user_event_meta_t("node", {"AddeD"})));
	EXPECT_TRUE(flt.allows(user_event_meta_t("node", {"eRRor"})));
	EXPECT_FALSE(flt.allows(user_event_meta_t("node", {"MODIFIED"})));
	EXPECT_TRUE(flt.allows(user_event_meta_t("pod", {"ADDED"})));
	flt.remove(evt);
	EXPECT_FALSE(flt.allows(evt));
	EXPECT_TRUE(flt.allows(evt0));
	EXPECT_TRUE(flt.allows(user_event_meta_t("nODe", {"ADDED"})));
	EXPECT_TRUE(flt.allows(user_event_meta_t("node", {"AddeD"})));
	EXPECT_TRUE(flt.allows(user_event_meta_t("node", {"eRRor"})));
	EXPECT_FALSE(flt.allows(user_event_meta_t("node", {"MODIFIED"})));
	EXPECT_FALSE(flt.allows(user_event_meta_t("pod", {"ADDED"})));
	flt.add(evt_all);
	EXPECT_TRUE(flt.allows(evt));
	EXPECT_TRUE(flt.allows(evt0));
	EXPECT_TRUE(flt.allows(user_event_meta_t("NODE", {"ADDED"})));
	EXPECT_TRUE(flt.allows(user_event_meta_t("node", {"AddeD"})));
	EXPECT_TRUE(flt.allows(user_event_meta_t("node", {"eRRor"})));
	EXPECT_TRUE(flt.allows(user_event_meta_t("node", {"MODIFIED"})));
	EXPECT_TRUE(flt.allows(user_event_meta_t("pod", {"ADDED"})));
	EXPECT_TRUE(flt.allows(user_event_meta_t("pod", {"ADDED", "MODIFIED", "DELETED", "ERROR"})));
    flt.clear();
	flt.add({"node", {"MODIFIED"}});
	EXPECT_TRUE(flt.allows(user_event_meta_t("Node", {"MODIFIED"})));
	flt.add({"all", {"all"}});
	EXPECT_TRUE(flt.allows_all("pod"));
	EXPECT_TRUE(flt.allows_all());
	EXPECT_TRUE(flt.allows(user_event_meta_t("NODE", {"MODIFIED"})));
	flt.clear();
	EXPECT_FALSE(flt.allows_all("pod"));
	EXPECT_FALSE(flt.allows_all("node"));
	EXPECT_FALSE(flt.allows_all());
}

TEST(user_event, scope)
{
	EXPECT_TRUE(event_scope::check_key_format("hostmac"));
	EXPECT_TRUE(event_scope::check_key_format("hostmac123"));
	EXPECT_TRUE(event_scope::check_key_format("host.mac"));
	EXPECT_TRUE(event_scope::check_key_format("host-mac"));
	EXPECT_TRUE(event_scope::check_key_format("host_mac"));
	EXPECT_TRUE(event_scope::check_key_format("host/mac"));
	EXPECT_FALSE(event_scope::check_key_format("host=mac"));
	EXPECT_FALSE(event_scope::check_key_format("host mac"));
	EXPECT_TRUE(event_scope::check_key_format("h_o.s/t-n_a--m/e.1_2-3/4"));

	event_scope es("host.mac", "00:1c:42:9a:bc:53");
	EXPECT_EQ(es.get(), "host.mac='00:1c:42:9a:bc:53'");
	es.add("container.id", "93015e6ddff4");
	EXPECT_EQ(es.get(), "host.mac='00:1c:42:9a:bc:53' and container.id='93015e6ddff4'");
	es.add("dummy", "some'thing", "or");
	EXPECT_EQ(es.get(), "host.mac='00:1c:42:9a:bc:53' and container.id='93015e6ddff4' or dummy='some\\'thing'");

	es.clear();
	es.add("host.mac", "00:1c:42:9a:bc:53");
	EXPECT_EQ(es.get(), "host.mac='00:1c:42:9a:bc:53'");
	es.add("container.id", "93015e6ddff4");
	EXPECT_EQ(es.get(), "host.mac='00:1c:42:9a:bc:53' and container.id='93015e6ddff4'");
	es.add("dummy", "some'thing", "or");
	EXPECT_EQ(es.get(), "host.mac='00:1c:42:9a:bc:53' and container.id='93015e6ddff4' or dummy='some\\'thing'");

	es.clear();
	es.add("host=mac", "00:1c:42:9a:bc:53");
	EXPECT_EQ(es.get(), "");

	es.clear();
	es.add("host mac", "00:1c:42:9a:bc:53");
	EXPECT_EQ(es.get(), "");

	es.clear();
	es.add("host.mac", "00:1c:42:'9a:bc:'53");
	EXPECT_EQ(es.get(), "host.mac='00:1c:42:\\'9a:bc:\\'53'");
}

TEST(user_event, event)
{
	event_scope scope;
	scope.add("host.mac", "00:1c:42:9a:bc:53");
	scope.add("container.image", "gcr.io/google_containers/kubernetes-dashboard-amd64:v1.5.1");
	std::string id("4280494e6a4b080246199030dcb7cb716f6c6492d8699d58e316ce22e758b573");
	scope.add("container.id", id.substr(0, 12));
	sinsp_user_event::tag_map_t tags{{"source", "docker"}};
	EXPECT_EQ(sinsp_user_event::to_string(static_cast<uint64_t>(~0), "Event Name", "Event Status", std::move(scope), std::move(tags)),
			  "timestamp: 18446744073709551615\n"
			  "name: \"Event Name\"\n"
			  "description: \"Event Status\"\n"
			  "scope: \"host.mac='00:1c:42:9a:bc:53' and container.image='gcr.io/google_containers/kubernetes-dashboard-amd64:v1.5.1' and container.id='4280494e6a4b'\"\n"
			  "tags:\n  \"source\": \"docker\"");
}
