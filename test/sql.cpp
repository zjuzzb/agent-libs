#define VISIBILITY_PRIVATE

#include <zlib.h>
#include <sinsp.h>
#include <sinsp_int.h>

#include "sys_call_test.h"
#include <gtest.h>
#include <algorithm>
#include "event_capture.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <event.h>
#include <sys/uio.h>
#include <Poco/Process.h>
#include <Poco/PipeStream.h>
#include <Poco/StringTokenizer.h>
#include <Poco/NumberFormatter.h>
#include <Poco/NumberParser.h>
#include <Poco/Path.h>
#include <list>
#include <cassert>
#include "parser_mysql.h"

using namespace std;
using Poco::StringTokenizer;
using Poco::NumberFormatter;
using Poco::NumberParser;
using Poco::Path;

#define DATA "josephine"

#define FILENAME "test_tmpfile"
#define DIRNAME "test_tmpdir"
#define UNEXISTENT_DIRNAME "/unexistent/pippo"

/////////////////////////////////////////////////////////////////////////////////////
// creat/unlink
/////////////////////////////////////////////////////////////////////////////////////
TEST_F(sys_call_test, sql_operation)
{
	char line[1024 * 16];
	gzFile zf;
	sinsp_autobuffer m_storage;
	sinsp_slq_query_parser p(&m_storage);

	zf = gzopen("sql.txt.gz", "rb");
	if(zf == NULL)
	{
		printf("sql.txt.gz not found, skipping test");

		return;
	}

//	set<string> opset;
	map<string, uint64_t> opmap;
	double duration = ((double)clock()) / CLOCKS_PER_SEC;
	uint64_t j = 0;


	while(gzgets(zf, line, sizeof(line)))
	{
//		printf("%s", line);
		p.parse(line, strlen(line));
/*
		if(p.m_operation_type == sinsp_slq_query_parser::OT_UPDATE)
		{
			printf("%s\t%s\n", line,
				p.get_statement_type_string());
		}
*/		
/*
		p.parse(line, strlen(line));
		
		opset.insert(line);
*/		

		string ops = p.get_statement_type_string();

		if(opmap.find(ops) == opmap.end())
		{
			opmap[ops] = 1;
		}
		else
		{
			opmap[ops]++;
		}

		j++;
	}

	duration = ((double)clock()) / CLOCKS_PER_SEC - duration;

	printf("#queries: %" PRIu64 "\n", j);
/*
	for(auto it = opset.begin(); it != opset.end(); ++it)
	{
		printf("%s\n", it->c_str());
	}
*/

	uint64_t tot = 0;
	for(auto it = opmap.begin(); it != opmap.end(); ++it)
	{
		printf("%s: %" PRIu64 "\n", it->first.c_str(), it->second);
		tot += it->second;
	}

	EXPECT_EQ(tot, j);
	EXPECT_EQ(opmap["CREATE"], 39846);
	EXPECT_EQ(opmap["DELETE"], 19880);
	EXPECT_EQ(opmap["DROP"], 49267);
	EXPECT_EQ(opmap["INSERT"], 118130);
	EXPECT_EQ(opmap["LOCK"], 19);
	EXPECT_EQ(opmap["REPLACE"], 3);
	EXPECT_EQ(opmap["SELECT"], 7198763);
	EXPECT_EQ(opmap["SET"], 11);
	EXPECT_EQ(opmap["SHOW"], 60);
	EXPECT_EQ(opmap["UNLOCK"], 19);
	EXPECT_EQ(opmap["UPDATE"], 16);

	printf("Elapsed time: %.3lf\n", duration);

	gzclose(zf);
}

TEST_F(sys_call_test, sql_table_select)
{
	char line[1024 * 16];
	gzFile zf;
	sinsp_autobuffer m_storage;
	sinsp_slq_query_parser p(&m_storage);

	zf = gzopen("sql.txt.gz", "rb");
	if(zf == NULL)
	{
		printf("sql.txt.gz not found, skipping test");

		return;
	}

	map<string, uint64_t> opmap;
	double duration = ((double)clock()) / CLOCKS_PER_SEC;
	uint64_t j = 0;


	while(gzgets(zf, line, sizeof(line)))
	{
		p.parse(line, strlen(line));

//		printf("%s", line);
		if(p.m_table && p.m_statement_type == sinsp_slq_query_parser::OT_SELECT)
		{
			string table = p.m_table;

			if(opmap.find(table) == opmap.end())
			{
				opmap[table] = 1;
			}
			else
			{
				opmap[table]++;
			}
		}

		j++;
	}

	duration = ((double)clock()) / CLOCKS_PER_SEC - duration;

	printf("#queries: %" PRIu64 "\n", j);

	uint64_t tot = 0;
	map<uint64_t, string> sorted_map;

	for(auto it = opmap.begin(); it != opmap.end(); ++it)
	{
//		printf("%s: %" PRIu64 "\n", it->first.c_str(), it->second);
		sorted_map[it->second] = it->first;
		tot += it->second;
	}
/*
	for(auto it = sorted_map.begin(); it != sorted_map.end(); ++it)
	{
		printf("%" PRIu64 " - %s\n", it->first, it->second.c_str());
	}
*/

	EXPECT_EQ(opmap["tab4"], 372459);
	EXPECT_EQ(opmap["( SELECT pk, col0 FROM tab0 WHERE (((((col0 < 94))))) )"], 1);
	EXPECT_EQ(opmap["( tab0 AS cor0 CROSS JOIN tab0 AS cor1 )"], 52);
	EXPECT_EQ(opmap["( SELECT pk, col0 FROM tab4 WHERE col3 IS NULL OR (col3 >= 422 OR (col3 > 734 AND (col3 < 813 OR col1 BETWEEN 30.88 AND 73.78) OR col4 >= 799.72)) AND (col3 >= 948) AND ((col3 > 52)) OR (col0 > 298) OR col1 < 283.19 OR col4 = 879.38 )"], 1);
	EXPECT_EQ(opmap["t15,t56,t18,t14,t43,t4,t1,t25,t31,t49,t27,t33,t52,t17,t20,t42,t55,t34,t8,t9,t7,t46,t53,t38,t3,t13,t45,t16,t24,t10,t47,t2,t35,t36,t57,t44"], 2);
	EXPECT_EQ(opmap["tab0 cor0 CROSS JOIN tab1"], 991);

	printf("Elapsed time: %.3lf\n", duration);

	gzclose(zf);
}

TEST_F(sys_call_test, sql_table_delete)
{
	char line[1024 * 16];
	gzFile zf;
	sinsp_autobuffer m_storage;
	sinsp_slq_query_parser p(&m_storage);

	zf = gzopen("sql.txt.gz", "rb");
	if(zf == NULL)
	{
		printf("sql.txt.gz not found, skipping test");

		return;
	}

	map<string, uint64_t> opmap;
	double duration = ((double)clock()) / CLOCKS_PER_SEC;
	uint64_t j = 0;


	while(gzgets(zf, line, sizeof(line)))
	{
		p.parse(line, strlen(line));

		if(p.m_table && p.m_statement_type == sinsp_slq_query_parser::OT_DELETE)
		{
//			printf("%s", line);
			string table = p.m_table;

			if(opmap.find(table) == opmap.end())
			{
				opmap[table] = 1;
			}
			else
			{
				opmap[table]++;
			}

			j++;
		}
	}

	duration = ((double)clock()) / CLOCKS_PER_SEC - duration;

	printf("#queries: %" PRIu64 "\n", j);

	uint64_t tot = 0;
	map<uint64_t, string> sorted_map;

	for(auto it = opmap.begin(); it != opmap.end(); ++it)
	{
		//printf("%s: %" PRIu64 "\n", it->first.c_str(), it->second);
		sorted_map[it->second] = it->first;
		tot += it->second;
	}
/*
	for(auto it = sorted_map.begin(); it != sorted_map.end(); ++it)
	{
		printf("%" PRIu64 " - %s\n", it->first, it->second.c_str());
	}
*/

	EXPECT_EQ(tot, j);
	EXPECT_EQ(opmap["tab1"], 3979);
	EXPECT_EQ(opmap["tab4"], 3973);
	EXPECT_EQ(opmap["view1"], 3);

	printf("Elapsed time: %.3lf\n", duration);

	gzclose(zf);
}

TEST_F(sys_call_test, sql_table_insert)
{
	char line[1024 * 16];
	gzFile zf;
	sinsp_autobuffer m_storage;
	sinsp_slq_query_parser p(&m_storage);

	zf = gzopen("sql.txt.gz", "rb");
	if(zf == NULL)
	{
		printf("sql.txt.gz not found, skipping test");

		return;
	}

	map<string, uint64_t> opmap;
	double duration = ((double)clock()) / CLOCKS_PER_SEC;
	uint64_t j = 0;


	while(gzgets(zf, line, sizeof(line)))
	{
		p.parse(line, strlen(line));

if(p.m_statement_type == sinsp_slq_query_parser::OT_INSERT)
{
	printf("!\n");		
}

		if(p.m_table && p.m_statement_type == sinsp_slq_query_parser::OT_INSERT)
		{
			printf("%s\n", p.m_table);
			string table = p.m_table;

			if(opmap.find(table) == opmap.end())
			{
				opmap[table] = 1;
			}
			else
			{
				opmap[table]++;
			}

			j++;
		}
	}

	duration = ((double)clock()) / CLOCKS_PER_SEC - duration;

	printf("#queries: %" PRIu64 "\n", j);

	uint64_t tot = 0;
	map<uint64_t, string> sorted_map;

	for(auto it = opmap.begin(); it != opmap.end(); ++it)
	{
		//printf("%s: %" PRIu64 "\n", it->first.c_str(), it->second);
		sorted_map[it->second] = it->first;
		tot += it->second;
	}
/*
	for(auto it = sorted_map.begin(); it != sorted_map.end(); ++it)
	{
		printf("%" PRIu64 " - %s\n", it->first, it->second.c_str());
	}
*/

	EXPECT_EQ(tot, j);
	EXPECT_EQ(opmap["tab1"], 3979);
	EXPECT_EQ(opmap["tab4"], 3973);
	EXPECT_EQ(opmap["view1"], 3);

	printf("Elapsed time: %.3lf\n", duration);

	gzclose(zf);
}
