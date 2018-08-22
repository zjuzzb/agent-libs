#define VISIBILITY_PRIVATE

#include <zlib.h>
#include <sinsp.h>

#include "sys_call_test.h"

using namespace std;

class sql_test : public testing::Test
{
};

/////////////////////////////////////////////////////////////////////////////////////
// quick test, doesn't need the sample file
/////////////////////////////////////////////////////////////////////////////////////
TEST_F(sql_test, quick)
{
	pair<string, string> queries[] = {
		{ "SELECT d, (SELECT count(*) FROM t1 AS x WHERE x.c>t1.c AND x.d<t1.d), c FROM t2 WHERE (e>a AND e<b) AND (e>c OR e<d) AND EXISTS(SELECT 1 FROM t3 AS x WHERE x.b<t1.b)", "t1, t2, t3"},
		{ "SELECT CASE WHEN c>(SELECT avg(c) FROM t1) THEN a*2 ELSE b*10 END FROM t1 ORDER BY 1", "t1"},
		{ "SELECT pk FROM tab0 WHERE ((col4 >= 5.12 AND col4 <= 2.44))", "tab0" },
		{ "SELECT ALL * FROM ( tab0 AS cor0 CROSS JOIN tab0 ) WHERE NOT NULL > ( NULL )", "tab0" },
		{ "SELECT e1 FROM t1 WHERE a1 in (767,433,637,363,776,109,451) OR c1 in (683,531,654,246,3,876,309,284) OR (b1=738) EXCEPT SELECT b8 FROM t8 WHERE NOT ((761=d8 AND b8=259 AND e8=44 AND 762=c8 AND 563=a8) OR e8 in (866,579,106,933)) EXCEPT SELECT e6 FROM t6 WHERE NOT ((825=b6 OR d6=500) OR (230=b6 AND e6=731 AND d6=355 AND 116=a6)) UNION SELECT b2 FROM t2 WHERE (d2=416) UNION SELECT a4 FROM t4 WHERE c4 in (806,119,489,658,366,424,2,471) OR (215=c4 OR c4=424 OR e4=405) UNION ALL SELECT a9 FROM t9 WHERE (e9=195) OR (c9=98 OR d9=145) UNION ALL SELECT e5 FROM t5 WHERE (44=c5 AND a5=362 AND 193=b5) OR (858=b5) UNION SELECT d3 FROM t3 WHERE (b3=152) OR (726=d3) UNION SELECT e7 FROM t7 WHERE d7 in (687,507,603,52,118) OR (d7=399 AND e7=408 AND 396=b7 AND a7=97 AND c7=813) OR (e7=605 OR 837=b7 OR e7=918)", "t1, t2, t3, t4, t5, t6, t7, t8, t9" },
		{ "INSERT INTO `QRTZ_FIRED_TRIGGERS` VALUES ('schedulerFactoryBean','draios@10.109.135.188:25521409636489814','6da64b5bd2ee-1cb99842-8069-435c-831a-9d58a3e4017b','DEFAULT','draios@10.109.135.188:2552',1410889894629,1410889894620,5,'EXECUTING','providers-29-13','providers',1,0),('schedulerFactoryBean','draios@10.109.135.188:25521409636489815','6da64b5bd2ee-ff63e46b-12e2-40c1-9b84-1bffe10eacb9','DEFAULT','draios@10.109.135.188:2552',1410889894700,1410889920000,5,'ACQUIRED',NULL,NULL,0,0)", "`QRTZ_FIRED_TRIGGERS`" },
		{ "INSERT INTO t1(e,c,b,d,a) VALUES(103,102,100,101,104)", "t1" },
		{ "SELECT CASE WHEN a<b-3 THEN 111 WHEN a<=b THEN 222 WHEN a<b+3 THEN 333 ELSE 444 END, d-e, b-c, d, a+b*2+c*3+d*4+e*5, (SELECT count(*) FROM t1 AS x WHERE x.b<t1.b), (a+b+c+d+e)/5 FROM t2 WHERE d NOT BETWEEN 110 AND 150 OR e+d BETWEEN a+b-10 AND c+130", "t1, t2" },
		{ "SELECT pk FROM tab4 WHERE col0 < 0 OR col0 IN (SELECT col3 FROM tab3 WHERE col3 >= 1) AND (col3 > 3 OR col1 <= 9.61 AND col3 < 6 AND (col4 > 6.43) AND ((col1 > 0.67)) AND col3 > 9 AND col3 <= 5 OR (((col1 >= 4.53 AND col1 <= 1.22))) AND (col3 < 4 AND ((((col0 > 1))) OR (((col0 = 1) AND col1 <= 4.83)) AND (((col3 >= 7)))) OR col3 >= 5) AND ((col4 > 5.40) AND col3 IN (0) OR (col4 >= 8.19) OR col4 < 2.84 OR ((((col1 < 8.18))))) AND col0 = 0 AND col3 IN (1,4,7,7) AND col0 <= 0 AND (col3 = 0) AND col0 < 2)", "tab3, tab4" },
		{ "SELECT * FROM tab0", "tab0" },
		{ "INSERT INTO tab1 SELECT * FROM tab0", "tab0, tab1" },
		{ "SELECT pk FROM (SELECT pk, col0 FROM tab0 WHERE ((col3 >= 40) OR col3 > 65 OR col3 >= 21 AND col4 > 41.37 AND (col4 > 96.1) AND col0 BETWEEN 95 AND 74) ) AS tab0_216", "tab0" },
		{ "SELECT pk FROM ( SELECT pk, col0 FROM tab0 WHERE ((col3 >= 40) OR col3 > 65 OR col3 >= 21 AND col4 > 41.37 AND (col4 > 96.1) AND col0 BETWEEN 95 AND 74) ) AS tab0_216", "tab0" },
		{ "SELECT pk FROM ( SELECT pk, col0 FROM tab3 WHERE (col3 IS NULL) OR col0 IS NULL AND col1 > 45.14 OR col4 <= 70.8 ) AS tab3_340", "tab3" },
		{ "SELECT ALL + + COUNT( * ) AS col1 FROM tab1 AS cor0 CROSS JOIN tab2 cor1", "tab1, tab2" },
		{ "SELECT ALL + + COUNT( * ) AS col1 FROM ( tab1 AS cor0 CROSS JOIN tab2 cor1 )", "tab1, tab2" },
		{ "SELECT 1 FROM t1 WHERE 1 IN ()", "t1" },
		{ "SELECT (1)FROM t1", "t1" },
		{ "SELECT qqfrom FROM t1", "t1" },
		{ "SELECT fromage", "" },
		{ "SELECT fromage from age", "age" },
		{ "DELETE FROM t1", "t1" },
		{ "SELECT COUNT( * ) * COUNT( * ) FROM tab0 AS cor0 CROSS JOIN tab0 AS cor1", "tab0" },
		{ "SELECT - COUNT( * ) + CAST( + 13 AS SIGNED ) col1 FROM tab1 AS cor0 CROSS JOIN tab0 AS cor1", "tab0, tab1" },
		{ "INSERT INTO `QRTZ_JOB_DETAILS` VALUES ('schedulerFactoryBean','baseline-1','baseline',NULL,'com.draios.jobs.baselines.BaselineJob',1,1,0,0,'��\0sr\0org.quartz.JobDataMap���迩��\0\0xr\0&org.quartz.utils.StringKeyDirtyFlagMap�����](\0Z\0allowsTransientDataxr\0org.quartz.utils.DirtyFlagMap�.�(v\n�\0Z\0dirtyL\0mapt\0Ljava/util/Map;xpsr\0java.util.HashMap���`�\0F\0\nloadFactorI\0	thresholdxp?@\0\0\0\0\0w\0\0\0\0\0\0t\0\ncustomerIdsr\0java.lang.Integer⠤���8\0I\0valuexr\0java.lang.Number������\0\0xp\0\0\0x\0'),('schedulerFactoryBean','baseline-10','baseline',NULL,'com.draios.jobs.baselines.BaselineJob',1,1,0,0,'��\0sr\0org.quartz.JobDataMap���迩��\0\0xr\0&org.quartz.utils.StringKeyDirtyFlagMap�����](\0Z\0allowsTransientDataxr\0org.quartz.utils.DirtyFlagMap�.�(v\n�\0Z\0dirtyL\0mapt\0Ljava/util/Map;xpsr\0java.util.HashMap���`�\0F\0\nloadFactorI\0	thresholdxp?@\0\0\0\0\0w\0\0\0\0\0\0t\0\ncustomerIdsr\0java.lang.Integer⠤���8\0I\0valuexr\0java.lang.Number������\0\0xp\0\0\0\nx\0'),('schedulerFactoryBean','baseline-11','baseline',NULL,'com.draios.jobs.baselines.BaselineJob',1,1,0,0,'��\0sr\0org.quartz.JobDataMap���迩��\0\0xr\0&org.quartz.utils.StringKeyDirtyFlagMap�����](\0Z\0allowsTransientDataxr\0org.quartz.utils.DirtyFlagMap�.�(v\n�\0Z\0dirtyL\0mapt\0Ljava/util/Map;xpsr\0java.util.HashMap���`�\0F\0\nloadFactorI\0	thresholdxp?@\0\0\0\0\0w\0\0\0\0\0\0t\0\ncustomerIdsr\0java.lang.Integer⠤���8\0I\0valuexr\0java.lang.Number������\0\0xp\0\0\0x\0'),('schedulerFactoryBean','baseline-12','baseline',NULL,'com.draios.jobs.baselines.BaselineJob',1,1,0,0,'��\0sr\0org.quartz.JobDataMap���迩��\0\0xr\0&org.quartz.utils.StringKeyDirtyFlagMap�����](\0Z\0allowsTransientDataxr\0org.quartz.utils.DirtyFlagMap�.�(v\n�\0Z\0dirtyL\0mapt\0Ljava/util/Map;xpsr\0java.util.HashMap���`�\0F\0\nloadFactorI\0	thresholdxp?@\0\0\0\0\0w\0\0\0\0\0\0t\0\ncustomerIdsr\0java.lan", "`QRTZ_JOB_DETAILS`" },
		{ "SELECT pk, col0 FROM tab0 WHERE (col3 < 204) AND col3 IN (SELECT col0 FROM tab0 WHERE col3 >= 218) AND col4 IN (SELECT col1 FROM tab0 WHERE (((((col3 IN (427) OR col3 <= 404)))) OR ((col0 IS NULL AND (col4 > 802.10 AND col0 = 651))) OR col3 BETWEEN 851 AND 573)) ORDER BY 1 DESC,2 DESC", "tab0" },
		{ "SELECT * FROM customers c LEFT OUTER JOIN customer_access_keys k ON k.id = ( SELECT kk.id FROM customer_access_keys kk WHERE kk.customer_id = c.id AND kk.enabled = TRUE ORDER BY kk.id LIMIT 1 )", "customer_access_keys, customers" },
	};

	sinsp_sql_parser sp;
	for (const auto& q: queries) {
		sp.parse(q.first.c_str(), q.first.size());
		EXPECT_EQ(q.second, sp.tables()) << q.first;
	}
}

TEST_F(sql_test, DISABLED_unsupported)
{
	pair<string, string> queries[] = {
		// we expect a space after a keyword
		{ "SELECT+1 FROM tab1 AS plus_one", "tab1" },

		// we don't handle quoted strings at all
		{ "SELECT \" SELECT * FROM t1 UNION SELECT ALL \" FROM t2", "t2" },
		{ "SELECT ' SELECT * FROM t1 UNION SELECT ALL ' FROM t2", "t2" },
		{ "SELECT ' SELECT '' FROM t1 UNION SELECT ALL ' FROM t2", "t2" },
		{ "SELECT $$ SELECT ' FROM t1 UNION SELECT ALL $$ FROM t2", "t2" },
		{ "SELECT $q$ SELECT ' FROM t1 UNION SELECT ALL $q$ FROM t2", "t2" },
		{ "SELECT E' SELECT \\' FROM t1 UNION SELECT ALL ' FROM t2", "t2" },

		// double quotes are valid around table names, at least in PostgreSQL
		// but we fail to find the table at all in this case
		{ "SELECT * FROM \"t2\"", "t2" },

		// MySQL allows backticks to quote database/table names
		// we support that but don't strip them from the result
		{ "SELECT * FROM `t2`", "t2" },
		{ "SELECT * FROM `dbname`.`t2`", "dbname.t2" }, // or maybe even t2?

		// no support for common table expressions (WITH ... queries)
		{ "WITH q AS (SELECT * FROM tab1) AS SELECT * FROM tab2, q", "tab1, tab2" },
	};

	sinsp_sql_parser sp;
	for (const auto& q: queries) {
		sp.parse(q.first.c_str(), q.first.size());
		EXPECT_EQ(q.second, sp.tables()) << q.first;
	}
}

/////////////////////////////////////////////////////////////////////////////////////
// full test, requires sql.txt.gz data file
/////////////////////////////////////////////////////////////////////////////////////
TEST_F(sql_test, full)
{
	char line[1024 * 16];
	gzFile zf;
	sinsp_sql_parser p;
	map<string, uint64_t> opmap;

	zf = gzopen("sql.txt.gz", "rb");
	if(zf == nullptr)
	{
		printf("sql.txt.gz not found, skipping test\n");
		return;
	}

	double duration = ((double)clock()) / CLOCKS_PER_SEC;
	while(gzgets(zf, line, sizeof(line)))
	{
		const char *q = strchr(line+2, '*');
		string exp(line+2, q-line-2);
		p.parse(q+2, strlen(q+2));

		auto table = p.tables();
		EXPECT_EQ(exp, table) << q+2;

		string ops = p.get_statement_type_string();
		EXPECT_NE(string("N/A"), ops);

		if(opmap.find(ops) == opmap.end())
		{
			opmap[ops] = 1;
		}
		else
		{
			opmap[ops]++;
		}

		ops.append(" ");
		ops.append(table);
		if(opmap.find(ops) == opmap.end())
		{
			opmap[ops] = 1;
		}
		else
		{
			opmap[ops]++;
		}
	}

	duration = ((double)clock()) / CLOCKS_PER_SEC - duration;
	printf("Elapsed time: %.3lf\n", duration);

	gzclose(zf);

	EXPECT_EQ(39846U, opmap["CREATE"]);
	EXPECT_EQ(19880U, opmap["DELETE"]);
	EXPECT_EQ(49267U, opmap["DROP"]);
	EXPECT_EQ(118129U, opmap["INSERT"]);
	EXPECT_EQ(19U, opmap["LOCK"]);
	EXPECT_EQ(3U, opmap["REPLACE"]);
	EXPECT_EQ(7198763U, opmap["SELECT"]);
	EXPECT_EQ(11U, opmap["SET"]);
	EXPECT_EQ(60U, opmap["SHOW"]);
	EXPECT_EQ(19U, opmap["UNLOCK"]);
	EXPECT_EQ(16U, opmap["UPDATE"]);

	EXPECT_EQ(1467377u, opmap["SELECT tab0"]);
	EXPECT_EQ(44974u, opmap["SELECT tab0, tab1"]);
	EXPECT_EQ(24212u, opmap["SELECT tab0, tab1, tab2"]);
	EXPECT_EQ(43987u, opmap["SELECT tab0, tab2"]);
	EXPECT_EQ(1466600u, opmap["SELECT tab1"]);
	EXPECT_EQ(44501u, opmap["SELECT tab1, tab2"]);
	EXPECT_EQ(1439742u, opmap["SELECT tab2"]);
	EXPECT_EQ(374089u, opmap["SELECT tab3"]);
	EXPECT_EQ(373893u, opmap["SELECT tab4"]);

	EXPECT_EQ(3979u, opmap["DELETE tab1"]);
	EXPECT_EQ(3973u, opmap["DELETE tab4"]);
	EXPECT_EQ(3u, opmap["DELETE view1"]);

	EXPECT_EQ(1167u, opmap["INSERT tab1"]);
	EXPECT_EQ(107009u, opmap["INSERT tab0"]);
	EXPECT_EQ(3u, opmap["INSERT view1"]);

	EXPECT_EQ(2u, opmap["REPLACE t1"]);

	EXPECT_EQ(13u, opmap["UPDATE t1"]);
	EXPECT_EQ(3u, opmap["UPDATE view1"]);
}
