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
TEST_F(sys_call_test, sql_extract_statement)
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
	set<string> opset;
	double duration = ((double)clock()) / CLOCKS_PER_SEC;
	uint32_t j = 0;


	while(gzgets(zf, line, sizeof(line)))
	{
		p.parse(line, strlen(line));
/*
		if(p.m_operation_type != sinsp_slq_query_parser::OT_SELECT)
		{
			printf("%s\t%s\n", line,
				p.get_operation_type_string());
		}
*/		
/*		
		if(strstr(line, "IF") == line)
		{
			printf("%s", line);
		}
*/
/*
		p.parse(line, strlen(line));
		
		opset.insert(line);
*/		
		j++;
	}

	duration = ((double)clock()) / CLOCKS_PER_SEC - duration;

	printf("*%d\n", j);

	for(auto it = opset.begin(); it != opset.end(); ++it)
	{
		printf("%s\n", it->c_str());
	}

	printf("Elapsed time: %.3lf\n", duration);

	gzclose(zf);
}
