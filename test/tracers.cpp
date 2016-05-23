#include <termios.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

#define VISIBILITY_PRIVATE
#define DR_TEST_APPEVT_PARSER

#include "sys_call_test.h"
#include <gtest.h>
#include <algorithm>
#include "event_capture.h"
#include <sys/stat.h>
#include <Poco/Process.h>
#include <Poco/PipeStream.h>
#include <list>
#include <cassert>
#include <event.h>
#include <Poco/StringTokenizer.h>
#include <Poco/NumberFormatter.h>
#include <Poco/NumberParser.h>

#if 1
#include <sinsp.h>
#include <sinsp_int.h>
#include <parsers.h>
#include "tracers.h"

using namespace std;

using Poco::StringTokenizer;
using Poco::NumberFormatter;
using Poco::NumberParser;


TEST_F(sys_call_test, tracers_1)
{
	sinsp_tracerparser p(NULL);

	char doc[] = "[\">\", 12435, [\"mysql\", \"query\", \"init\"], [{\"argname1\":\"argval1\"}, {\"argname2\":\"argval2\"}, {\"argname3\":\"argval3\"}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_OK, p.m_res);
	EXPECT_EQ(">", string(p.m_type_str));
	EXPECT_EQ(12435, (int)p.m_id);
	EXPECT_EQ(3, (int)p.m_tags.size());
	EXPECT_EQ(3, (int)p.m_argnames.size());
	EXPECT_EQ(3, (int)p.m_argvals.size());
}

TEST_F(sys_call_test, tracers_2)
{
	sinsp_tracerparser p(NULL);

	char doc[] = "[, <, [\"mysql\"], [{\"argname1\":\"argval1\"}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_NE(sinsp_tracerparser::RES_OK, p.m_res);
}

TEST_F(sys_call_test, tracers_3)
{
	sinsp_tracerparser p(NULL);

	char doc[] = "[123, a, [\"mysql\"], [{\"argname1\":\"argval1\"}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_FAILED, p.m_res);
}

TEST_F(sys_call_test, tracers_4)
{
	sinsp_tracerparser p(NULL);

	char doc[] = "[123 >, [\"mysql\"], [{\"argname1\":\"argval1\"}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_FAILED, p.m_res);
}

TEST_F(sys_call_test, tracers_5)
{
	sinsp_tracerparser p(NULL);

	char doc[] = "[123, > [\"mysql\"], [{\"argname1\":\"argval1\"}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_FAILED, p.m_res);
}

TEST_F(sys_call_test, tracers_6)
{
	sinsp_tracerparser p(NULL);

	char doc[] = "[\">\", 123, [\"mysql\"] [{\"argname1\":\"argval1\"}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_FAILED, p.m_res);
}

TEST_F(sys_call_test, tracers_7)
{
	sinsp_tracerparser p(NULL);

	char doc[] = "[\">\", 123, \"mysql\"], [{\"argname1\":\"argval1\"}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_FAILED, p.m_res);
}

TEST_F(sys_call_test, tracers_8)
{
	sinsp_tracerparser p(NULL);

	char doc[] = "[\">\", 123, [\"mysql\", [{\"argname1\":\"argval1\"}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_FAILED, p.m_res);
}

TEST_F(sys_call_test, tracers_9)
{
	sinsp_tracerparser p(NULL);

	char doc[] = "[\">\", 123, \"mysql\", [{\"argname1\":\"argval1\"}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_FAILED, p.m_res);
}

TEST_F(sys_call_test, tracers_10)
{
	sinsp_tracerparser p(NULL);

	char doc[] = "[[123], >, [\"mysql\"], [{\"argname1\":\"argval1\"}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_FAILED, p.m_res);
}

TEST_F(sys_call_test, tracers_11)
{
	sinsp_tracerparser p(NULL);

	char doc[] = "[[\">\", 123, [\"mysql\"], [{\"argname1\":\"argval1\"}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_FAILED, p.m_res);
}

TEST_F(sys_call_test, tracers_12)
{
	sinsp_tracerparser p(NULL);

	char doc[] = "[\">\", 123, [\"mysql\"], [\"argname1\":\"argval1\"}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_FAILED, p.m_res);
}

TEST_F(sys_call_test, tracers_13)
{
	sinsp_tracerparser p(NULL);

	char doc[] = "[\">\", 123, [\"mysql\"], [{\"argname1\":\"argval1\"]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_FAILED, p.m_res);
}

TEST_F(sys_call_test, tracers_14)
{
	sinsp_tracerparser p(NULL);

	char doc[] = "[\">\", 123, [\"mysql\"], [\"argname1\":\"argval1\"]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_FAILED, p.m_res);
}

TEST_F(sys_call_test, tracers_15)
{
	sinsp_tracerparser p(NULL);

	char doc[] = "[\">\", 123, [\"mysql\"], [{\"argname1\":\"argval1\"}, {\"argname1\":\"argval1\"]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_FAILED, p.m_res);
}

TEST_F(sys_call_test, tracers_16)
{
	sinsp_tracerparser p(NULL);

	char doc[] = "[\">\", 123, [\"mysql\"], [{\"argname1\":\"argval1\"}, \"argname1\":\"argval1\"]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_FAILED, p.m_res);
}

TEST_F(sys_call_test, tracers_17)
{
	sinsp_tracerparser p(NULL);

	char doc[] = "[\">\", 123, [mysql], [{\"argname1\":\"argval1\"}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_FAILED, p.m_res);
}

TEST_F(sys_call_test, tracers_18)
{
	sinsp_tracerparser p(NULL);

	char doc[] = "[\">\", 123, [\"mysql\"], [{argname1:\"argval1\"}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_FAILED, p.m_res);
}

TEST_F(sys_call_test, tracers_19)
{
	sinsp_tracerparser p(NULL);

	char doc[] = "[\">\", 123, [\"mysql\"], [{\"argname1\":argval1}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_FAILED, p.m_res);
}

TEST_F(sys_call_test, tracers_20)
{
	sinsp_tracerparser p(NULL);

	char doc[] = "[\">\", 123, [\"mysql\"], [{\"argname1\":\"argval1\"}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_OK, p.m_res);
}

TEST_F(sys_call_test, tracers_21)
{
	sinsp_tracerparser p(NULL);

	char doc[] = "[\">\", 123, [\"mysql\"], [{\"argname1\":\"argval1\"}, {\"argname1\":\"argval1\"}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_OK, p.m_res);
}

TEST_F(sys_call_test, tracers_22)
{
	sinsp_tracerparser p(NULL);

	char doc[] = "[\">\", 123, [\"mysql\"], [{\"argname1\":\"argval1\"} {\"argname1\":\"argval1\"}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_FAILED, p.m_res);
}

TEST_F(sys_call_test, tracers_23)
{
	sinsp_tracerparser p(NULL);

	char doc[] = "[\">\", 123, [\"mysql\"], [{\"argname1\":\"argval1\"}{\"argname1\":\"argval1\"}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_FAILED, p.m_res);
}

TEST_F(sys_call_test, tracers_24)
{
	sinsp_tracerparser p(NULL);

	char doc[] = "[\">\", 12, [\"mysql\"], []]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_OK, p.m_res);
	EXPECT_EQ(">", string(p.m_type_str));
	EXPECT_EQ(12, (int)p.m_id);
	EXPECT_EQ(1, (int)p.m_tags.size());
	EXPECT_EQ(0, (int)p.m_argnames.size());
	EXPECT_EQ(0, (int)p.m_argvals.size());
}

TEST_F(sys_call_test, tracers_25)
{
	sinsp_tracerparser p(NULL);

	char doc[] = "[\">\", 12, [], [{\"argname1\":\"argval1\"}, {\"argname2\":\"argval2\"}]]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_OK, p.m_res);
	EXPECT_EQ(">", string(p.m_type_str));
	EXPECT_EQ(12, (int)p.m_id);
	EXPECT_EQ(0, (int)p.m_tags.size());
	EXPECT_EQ(2, (int)p.m_argnames.size());
	EXPECT_EQ(2, (int)p.m_argvals.size());
}

TEST_F(sys_call_test, tracers_26)
{
	sinsp_tracerparser p(NULL);

	char doc[] = "[\">\", 12, [], []]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_OK, p.m_res);
	EXPECT_EQ(">", string(p.m_type_str));
	EXPECT_EQ(12, (int)p.m_id);
	EXPECT_EQ(0, (int)p.m_tags.size());
	EXPECT_EQ(0, (int)p.m_argnames.size());
	EXPECT_EQ(0, (int)p.m_argvals.size());
}

TEST_F(sys_call_test, tracers_27)
{
	sinsp_tracerparser p(NULL);

	char doc[] = "        [\">\", 12, [], []]]        ";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_OK, p.m_res);
	EXPECT_EQ(">", string(p.m_type_str));
	EXPECT_EQ(12, (int)p.m_id);
	EXPECT_EQ(0, (int)p.m_tags.size());
	EXPECT_EQ(0, (int)p.m_argnames.size());
	EXPECT_EQ(0, (int)p.m_argvals.size());
}

TEST_F(sys_call_test, tracers_28)
{
	sinsp_tracerparser p(NULL);

	char doc[] = "        [\">\"             ,      12  , [], [  ]    ]         ]        ";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_OK, p.m_res);
	EXPECT_EQ(">", string(p.m_type_str));
	EXPECT_EQ(12, (int)p.m_id);
	EXPECT_EQ(0, (int)p.m_tags.size());
	EXPECT_EQ(0, (int)p.m_argnames.size());
	EXPECT_EQ(0, (int)p.m_argvals.size());
}

TEST_F(sys_call_test, tracers_29)
{
	sinsp_tracerparser p(NULL);

	char doc[] = "[\">\", ";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_TRUNCATED, p.m_res);
}

TEST_F(sys_call_test, tracers_31)
{
	sinsp_tracerparser p(NULL);

	char doc1[] = "[\">\", 12435, [\"mysql\", \"query\", \"in";
	char doc2[] = "it\"], [{\"argname1\":\"argval1\"}, {\"argname2\":\"argval2\"";
	char doc3[] = "}, {\"argname3\":\"argval3\"}]]";

	p.process_event_data(doc1, sizeof(doc1) - 1, 10);
	EXPECT_EQ(sinsp_tracerparser::RES_TRUNCATED, p.m_res);

	p.process_event_data(doc2, sizeof(doc2) - 1, 10);
	EXPECT_EQ(sinsp_tracerparser::RES_TRUNCATED, p.m_res);

	p.process_event_data(doc3, sizeof(doc3) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_OK, p.m_res);
	EXPECT_EQ(">", string(p.m_type_str));
	EXPECT_EQ(12435, (int)p.m_id);
	EXPECT_EQ(3, (int)p.m_tags.size());
	EXPECT_EQ(3, (int)p.m_argnames.size());
	EXPECT_EQ(3, (int)p.m_argvals.size());
}

TEST_F(sys_call_test, tracers_32)
{
	sinsp_tracerparser p(NULL);

	char doc1[] = "[\">\", 12435, [\"mysql\", \"query\"";
	char doc2[] = ", \"init\"], [{\"argname1\":\"argval1\"}, {\"argname2\":";
	char doc3[] = "\"argval2\"}, {\"argname3\":\"argval3\"}]]";

	p.process_event_data(doc1, sizeof(doc1) - 1, 10);
	EXPECT_EQ(sinsp_tracerparser::RES_TRUNCATED, p.m_res);

	p.process_event_data(doc2, sizeof(doc2) - 1, 10);
	EXPECT_EQ(sinsp_tracerparser::RES_TRUNCATED, p.m_res);

	p.process_event_data(doc3, sizeof(doc3) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_OK, p.m_res);
	EXPECT_EQ(">", string(p.m_type_str));
	EXPECT_EQ(12435, (int)p.m_id);
	EXPECT_EQ(3, (int)p.m_tags.size());
	EXPECT_EQ(3, (int)p.m_argnames.size());
	EXPECT_EQ(3, (int)p.m_argvals.size());
}

TEST_F(sys_call_test, tracers_33)
{
	sinsp_tracerparser p(NULL);

	char doc1[] = "[\">\", 12435, [\"mys";
	char doc2[] = "ql\", \"query\", \"init\"], [{\"argname1\":\"argval1\"}";
	char doc3[] = ", {\"argname2\":\"argval2\"}, {\"argname3\":\"argval3\"}]]";

	p.process_event_data(doc1, sizeof(doc1) - 1, 10);
	EXPECT_EQ(sinsp_tracerparser::RES_TRUNCATED, p.m_res);

	p.process_event_data(doc2, sizeof(doc2) - 1, 10);
	EXPECT_EQ(sinsp_tracerparser::RES_TRUNCATED, p.m_res);

	p.process_event_data(doc3, sizeof(doc3) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_OK, p.m_res);
	EXPECT_EQ(">", string(p.m_type_str));
	EXPECT_EQ(12435, (int)p.m_id);
	EXPECT_EQ(3, (int)p.m_tags.size());
	EXPECT_EQ(3, (int)p.m_argnames.size());
	EXPECT_EQ(3, (int)p.m_argvals.size());
}

TEST_F(sys_call_test, tracers_34)
{
	sinsp_tracerparser p(NULL);

	char doc1[] = "[\">\", 12435,";
	char doc2[] = " [\"mysql\", \"query\", ";
	char doc3[] = "\"init\"], [{\"argname1\":\"argval1\"}, {\"argname2\":\"argval2\"}, {\"argname3\":\"argval3\"}]]";

	p.process_event_data(doc1, sizeof(doc1) - 1, 10);
	EXPECT_EQ(sinsp_tracerparser::RES_TRUNCATED, p.m_res);

	p.process_event_data(doc2, sizeof(doc2) - 1, 10);
	EXPECT_EQ(sinsp_tracerparser::RES_TRUNCATED, p.m_res);

	p.process_event_data(doc3, sizeof(doc3) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_OK, p.m_res);
	EXPECT_EQ(">", string(p.m_type_str));
	EXPECT_EQ(12435, (int)p.m_id);
	EXPECT_EQ(3, (int)p.m_tags.size());
	EXPECT_EQ(3, (int)p.m_argnames.size());
	EXPECT_EQ(3, (int)p.m_argvals.size());
}

TEST_F(sys_call_test, tracers_35)
{
	sinsp_tracerparser p(NULL);

	char doc1[] = "[\">\", 12435";
	char doc2[] = ", [\"mysql\", \"query\",";
	char doc3[] = " \"init\"], [{\"argname1\":\"argval1\"}, {\"argname2\":\"argval2\"}, {\"argname3\":\"argval3\"}]]";

	p.process_event_data(doc1, sizeof(doc1) - 1, 10);
	EXPECT_EQ(sinsp_tracerparser::RES_TRUNCATED, p.m_res);

	p.process_event_data(doc2, sizeof(doc2) - 1, 10);
	EXPECT_EQ(sinsp_tracerparser::RES_TRUNCATED, p.m_res);

	p.process_event_data(doc3, sizeof(doc3) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_OK, p.m_res);
	EXPECT_EQ(">", string(p.m_type_str));
	EXPECT_EQ(12435, (int)p.m_id);
	EXPECT_EQ(3, (int)p.m_tags.size());
	EXPECT_EQ(3, (int)p.m_argnames.size());
	EXPECT_EQ(3, (int)p.m_argvals.size());
}

TEST_F(sys_call_test, tracers_39)
{
	sinsp_tracerparser p(NULL);

	char doc1[] = "";
	char doc2[] = "";
	char doc3[] = "[\">\", 12435, [\"mysql\", \"query\", \"init\"], [{\"argname1\":\"argval1\"}, {\"argname2\":\"argval2\"}, {\"argname3\":\"argval3\"}]]";

	p.process_event_data(doc1, sizeof(doc1) - 1, 10);
	EXPECT_EQ(sinsp_tracerparser::RES_FAILED, p.m_res);

	p.process_event_data(doc2, sizeof(doc2) - 1, 10);
	EXPECT_EQ(sinsp_tracerparser::RES_FAILED, p.m_res);

	p.process_event_data(doc3, sizeof(doc3) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_OK, p.m_res);
	EXPECT_EQ(">", string(p.m_type_str));
	EXPECT_EQ(12435, (int)p.m_id);
	EXPECT_EQ(3, (int)p.m_tags.size());
	EXPECT_EQ(3, (int)p.m_argnames.size());
	EXPECT_EQ(3, (int)p.m_argvals.size());
}

TEST_F(sys_call_test, tracers_40)
{
	sinsp_tracerparser p(NULL);
	char tb[2];
	tb[1] = 0;
	uint32_t k;

	char doc[] = "[\">\", 12435, [\"mysql\", \"query\", \"init\"], [{\"argname1\":\"argval1\"}, {\"argname2\":\"argval2\"}, {\"argname3\":\"argval3\"}]]";

	for(k = 0; k < sizeof(doc) - 2; k++)
	{
		tb[0] = doc[k];
		p.process_event_data(tb, 1, 10);
		EXPECT_EQ(sinsp_tracerparser::RES_TRUNCATED, p.m_res);
	}

	tb[0] = doc[k];
	p.process_event_data(tb, 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_OK, p.m_res);
	EXPECT_EQ(">", string(p.m_type_str));
	EXPECT_EQ(12435, (int)p.m_id);
	EXPECT_EQ(3, (int)p.m_tags.size());
	EXPECT_EQ(3, (int)p.m_argnames.size());
	EXPECT_EQ(3, (int)p.m_argvals.size());
}

TEST_F(sys_call_test, tracers_41)
{
	sinsp_tracerparser p(NULL);

	char doc[] = "[\"\\\">\", 12435, [\"my\\\"\\\"sql\", \"query\", \"init\"], [{\"argname1\":\"argval1\"}, {\"argname2\":\"argval2\"}, {\"argname3\":\"argval3\"}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_OK, p.m_res);
	EXPECT_EQ("\\\">", string(p.m_type_str));
	EXPECT_EQ(12435, (int)p.m_id);
	EXPECT_EQ(3, (int)p.m_tags.size());
	EXPECT_EQ(3, (int)p.m_argnames.size());
	EXPECT_EQ(3, (int)p.m_argvals.size());
}

TEST_F(sys_call_test, tracers_fast_1)
{
	sinsp_tracerparser p(NULL);

	char doc[] = ">:12435:mysql.query.init:argname1=argval1,argname2=argval2,argname3=argval3:";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_OK, p.m_res);
	EXPECT_EQ(">", string(p.m_type_str));
	EXPECT_EQ(12435, (int)p.m_id);
	EXPECT_EQ(string("mysql"), string(p.m_tags[0]));
	EXPECT_EQ(string("query"), string(p.m_tags[1]));
	EXPECT_EQ(string("init"), string(p.m_tags[2]));
	EXPECT_EQ(3, (int)p.m_tags.size());
	EXPECT_EQ(3, (int)p.m_argnames.size());
	EXPECT_EQ(3, (int)p.m_argvals.size());
}

TEST_F(sys_call_test, tracers_fast_2)
{
	sinsp_tracerparser p(NULL);

	char doc[] = ">::mysql.query.init:argname1=argval1,argname2=argval2,argname3=argval3:";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_OK, p.m_res);
	EXPECT_EQ(">", string(p.m_type_str));
	EXPECT_EQ(0, (int)p.m_id);
	EXPECT_EQ(3, (int)p.m_tags.size());
	EXPECT_EQ(3, (int)p.m_argnames.size());
	EXPECT_EQ(3, (int)p.m_argvals.size());
}

TEST_F(sys_call_test, tracers_fast_3)
{
	sinsp_tracerparser p(NULL);

	char doc[] = "<::mysql.query:argname1=argval1,argname2=argval2,argname3=argval3:";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_OK, p.m_res);
	EXPECT_EQ("<", string(p.m_type_str));
	EXPECT_EQ(0, (int)p.m_id);
	EXPECT_EQ(2, (int)p.m_tags.size());
	EXPECT_EQ(3, (int)p.m_argnames.size());
	EXPECT_EQ(3, (int)p.m_argvals.size());
}

TEST_F(sys_call_test, tracers_fast_4)
{
	sinsp_tracerparser p(NULL);

	char doc[] = "<:12345:mysql:argname1=argval1,argname2=argval2,argname3=argval3:";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_OK, p.m_res);
	EXPECT_EQ("<", string(p.m_type_str));
	EXPECT_EQ(12345, (int)p.m_id);
	EXPECT_EQ(1, (int)p.m_tags.size());
	EXPECT_EQ(string("mysql"), string(p.m_tags[0]));
	EXPECT_EQ(3, (int)p.m_argnames.size());
	EXPECT_EQ(3, (int)p.m_argvals.size());
}

TEST_F(sys_call_test, tracers_fast_5)
{
	sinsp_tracerparser p(NULL);

	char doc[] = "-:12345:mysql:argname1=argval1,argname2=argval2,argname3=argval3:";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_NE(sinsp_tracerparser::RES_OK, p.m_res);
}

TEST_F(sys_call_test, tracers_fast_6)
{
	sinsp_tracerparser p(NULL);

	char doc[] = ":12345:mysql:argname1=argval1,argname2=argval2,argname3=argval3:";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_NE(sinsp_tracerparser::RES_OK, p.m_res);
}

TEST_F(sys_call_test, tracers_fast_7)
{
	sinsp_tracerparser p(NULL);

	char doc[] = ">:123";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_TRUNCATED, p.m_res);
}

TEST_F(sys_call_test, tracers_fast_8)
{
	sinsp_tracerparser p(NULL);

	char doc[] = ">:12345:mysql:argnam";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_TRUNCATED, p.m_res);
}

TEST_F(sys_call_test, tracers_fast_9)
{
	sinsp_tracerparser p(NULL);

	char doc[] = ">::mysql.query.init:argname1=arg:";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_OK, p.m_res);
}

TEST_F(sys_call_test, tracers_fast_10)
{
	sinsp_tracerparser p(NULL);

	char doc[] = ">:12345:mysql:argname1=argval1,";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_TRUNCATED, p.m_res);
}

TEST_F(sys_call_test, tracers_fast_11)
{
	sinsp_tracerparser p(NULL);

	char doc[] = ">::mysql.";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_TRUNCATED, p.m_res);
}

TEST_F(sys_call_test, tracers_fast_12)
{
	sinsp_tracerparser p(NULL);

	char doc[] = ">:12345:mysql:argname1=argval1:";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_OK, p.m_res);
	EXPECT_EQ(">", string(p.m_type_str));
	EXPECT_EQ(12345, (int)p.m_id);
	EXPECT_EQ(1, (int)p.m_tags.size());
	EXPECT_EQ(string("mysql"), string(p.m_tags[0]));
	EXPECT_EQ(1, (int)p.m_argnames.size());
	EXPECT_EQ(1, (int)p.m_argvals.size());
	EXPECT_EQ(string("argname1"), string(p.m_argnames[0]));
	EXPECT_EQ(string("argval1"), string(p.m_argvals[0]));
}

TEST_F(sys_call_test, tracers_fast_13)
{
	sinsp_tracerparser p(NULL);

	char doc[] = ">:12345:mysql:argname1=argval1,argname2=argval2,argname3=argval3:";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_OK, p.m_res);
	EXPECT_EQ(">", string(p.m_type_str));
	EXPECT_EQ(12345, (int)p.m_id);
	EXPECT_EQ(1, (int)p.m_tags.size());
	EXPECT_EQ(string("mysql"), string(p.m_tags[0]));
	EXPECT_EQ(3, (int)p.m_argnames.size());
	EXPECT_EQ(3, (int)p.m_argvals.size());
	EXPECT_EQ(string("argname1"), string(p.m_argnames[0]));
	EXPECT_EQ(string("argval1"), string(p.m_argvals[0]));
	EXPECT_EQ(string("argname2"), string(p.m_argnames[1]));
	EXPECT_EQ(string("argval2"), string(p.m_argvals[1]));
	EXPECT_EQ(string("argname3"), string(p.m_argnames[2]));
	EXPECT_EQ(string("argval3"), string(p.m_argvals[2]));
}

TEST_F(sys_call_test, tracers_fast_14)
{
	sinsp_tracerparser p(NULL);

	char doc[] = ">::mysql.query.init:argname1=arg";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_TRUNCATED, p.m_res);
}

TEST_F(sys_call_test, tracers_fast_15)
{
	sinsp_tracerparser p(NULL);
	char tb1[256];
	char tb2[256];
	uint32_t k;

	char doc[] = ">:12345:mysql.a.b:argname1=argval1,argname2=argval2,argname3=argval3:";

	for(k = 0; k < sizeof(doc) - 1; k++)
	{
		memcpy(tb1, doc, k);
		memcpy(tb2, doc + k, sizeof(doc) - k);
		tb1[k] = 0;
		tb2[sizeof(doc) - k] = 0;
		//printf("*%d-%d :: %s :: %s\n", k, (int)sizeof(doc) - k, tb1, tb2);

		p.process_event_data(tb1, k, 10);
		EXPECT_NE(sinsp_tracerparser::RES_OK, p.m_res);

		p.process_event_data(tb2, sizeof(doc) - k, 10);

		EXPECT_EQ(sinsp_tracerparser::RES_OK, p.m_res);		
		EXPECT_EQ(">", string(p.m_type_str));
		EXPECT_EQ(12345, (int)p.m_id);
		EXPECT_EQ(3, (int)p.m_tags.size());
		EXPECT_EQ(3, (int)p.m_argnames.size());
		EXPECT_EQ(3, (int)p.m_argvals.size());
	}
}

TEST_F(sys_call_test, tracers_fast_16)
{
	sinsp_tracerparser p(NULL);

	char doc[] = ">:12345:mysql::";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_OK, p.m_res);
	EXPECT_EQ(">", string(p.m_type_str));
	EXPECT_EQ(12345, (int)p.m_id);
	EXPECT_EQ(1, (int)p.m_tags.size());
	EXPECT_EQ(string("mysql"), string(p.m_tags[0]));
}

TEST_F(sys_call_test, DISABLED_tracers_fast_17)
{
	sinsp_tracerparser p(NULL);

	char doc[] = ">:1111:u\\:\\>.aaa.u\\:\\=a.33.aa\\::a=b\\:\\=,c=d\\:\\=a:";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_tracerparser::RES_OK, p.m_res);
	EXPECT_EQ(">", string(p.m_type_str));
	EXPECT_EQ(1111, (int)p.m_id);
	EXPECT_EQ(5, (int)p.m_tags.size());
	EXPECT_EQ(string("u:>"), string(p.m_tags[0]));
	EXPECT_EQ(string("aaa"), string(p.m_tags[1]));
	EXPECT_EQ(string("u:=a"), string(p.m_tags[2]));
	EXPECT_EQ(string("33"), string(p.m_tags[3]));
	EXPECT_EQ(string("aa:"), string(p.m_tags[4]));
	EXPECT_EQ(2, (int)p.m_argnames.size());
	EXPECT_EQ(2, (int)p.m_argvals.size());
	EXPECT_EQ(string("a"), string(p.m_argnames[0]));
	EXPECT_EQ(string("c"), string(p.m_argnames[1]));
	EXPECT_EQ(string("b:="), string(p.m_argvals[0]));
	EXPECT_EQ(string("d:=a"), string(p.m_argvals[1]));
}

#endif // 0