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

	zf = gzopen("sql.txt.gz", "rb");
	if(zf == NULL)
	{
		printf("sql.txt.gz not found, skipping test");

		return;
	}

	sinsp_slq_query_parser p;
//	set<string> opset;
	map<string, uint64_t> opmap;
	double duration = ((double)clock()) / CLOCKS_PER_SEC;
	uint64_t j = 0;


	while(gzgets(zf, line, sizeof(line)))
	{
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
	EXPECT_EQ(opmap["DROP"], 34687);
	EXPECT_EQ(opmap["INSERT"], 118130);
	EXPECT_EQ(opmap["LOCK"], 19);
	EXPECT_EQ(opmap["REPLACE"], 3);
	EXPECT_EQ(opmap["SELECT"], 7213343);
	EXPECT_EQ(opmap["SET"], 11);
	EXPECT_EQ(opmap["SHOW"], 60);
	EXPECT_EQ(opmap["UNLOCK"], 19);
	EXPECT_EQ(opmap["UPDATE"], 16);

	printf("Elapsed time: %.3lf\n", duration);

	gzclose(zf);
}
