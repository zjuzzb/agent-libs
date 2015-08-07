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
#include "markers.h"

using namespace std;

using Poco::StringTokenizer;
using Poco::NumberFormatter;
using Poco::NumberParser;


TEST_F(sys_call_test, markers_1)
{
	sinsp_markerparser p(NULL);

	char doc[] = "[\">\", 12435, [\"mysql\", \"query\", \"init\"], [{\"argname1\":\"argval1\"}, {\"argname2\":\"argval2\"}, {\"argname3\":\"argval3\"}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_markerparser::RES_OK, p.m_res);
	EXPECT_EQ(">", string(p.m_type_str));
	EXPECT_EQ(12435, (int)p.m_id);
	EXPECT_EQ(3, (int)p.m_tags.size());
	EXPECT_EQ(3, (int)p.m_argnames.size());
	EXPECT_EQ(3, (int)p.m_argvals.size());
}

TEST_F(sys_call_test, markers_2)
{
	sinsp_markerparser p(NULL);

	char doc[] = "[, <, [\"mysql\"], [{\"argname1\":\"argval1\"}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_NE(sinsp_markerparser::RES_OK, p.m_res);
}

TEST_F(sys_call_test, markers_3)
{
	sinsp_markerparser p(NULL);

	char doc[] = "[123, a, [\"mysql\"], [{\"argname1\":\"argval1\"}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_markerparser::RES_FAILED, p.m_res);
}

TEST_F(sys_call_test, markers_4)
{
	sinsp_markerparser p(NULL);

	char doc[] = "[123 >, [\"mysql\"], [{\"argname1\":\"argval1\"}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_markerparser::RES_FAILED, p.m_res);
}

TEST_F(sys_call_test, markers_5)
{
	sinsp_markerparser p(NULL);

	char doc[] = "[123, > [\"mysql\"], [{\"argname1\":\"argval1\"}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_markerparser::RES_FAILED, p.m_res);
}

TEST_F(sys_call_test, markers_6)
{
	sinsp_markerparser p(NULL);

	char doc[] = "[\">\", 123, [\"mysql\"] [{\"argname1\":\"argval1\"}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_markerparser::RES_FAILED, p.m_res);
}

TEST_F(sys_call_test, markers_7)
{
	sinsp_markerparser p(NULL);

	char doc[] = "[\">\", 123, \"mysql\"], [{\"argname1\":\"argval1\"}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_markerparser::RES_FAILED, p.m_res);
}

TEST_F(sys_call_test, markers_8)
{
	sinsp_markerparser p(NULL);

	char doc[] = "[\">\", 123, [\"mysql\", [{\"argname1\":\"argval1\"}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_markerparser::RES_FAILED, p.m_res);
}

TEST_F(sys_call_test, markers_9)
{
	sinsp_markerparser p(NULL);

	char doc[] = "[\">\", 123, \"mysql\", [{\"argname1\":\"argval1\"}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_markerparser::RES_FAILED, p.m_res);
}

TEST_F(sys_call_test, markers_10)
{
	sinsp_markerparser p(NULL);

	char doc[] = "[[123], >, [\"mysql\"], [{\"argname1\":\"argval1\"}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_markerparser::RES_FAILED, p.m_res);
}

TEST_F(sys_call_test, markers_11)
{
	sinsp_markerparser p(NULL);

	char doc[] = "[[\">\", 123, [\"mysql\"], [{\"argname1\":\"argval1\"}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_markerparser::RES_FAILED, p.m_res);
}

TEST_F(sys_call_test, markers_12)
{
	sinsp_markerparser p(NULL);

	char doc[] = "[\">\", 123, [\"mysql\"], [\"argname1\":\"argval1\"}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_markerparser::RES_FAILED, p.m_res);
}

TEST_F(sys_call_test, markers_13)
{
	sinsp_markerparser p(NULL);

	char doc[] = "[\">\", 123, [\"mysql\"], [{\"argname1\":\"argval1\"]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_markerparser::RES_FAILED, p.m_res);
}

TEST_F(sys_call_test, markers_14)
{
	sinsp_markerparser p(NULL);

	char doc[] = "[\">\", 123, [\"mysql\"], [\"argname1\":\"argval1\"]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_markerparser::RES_FAILED, p.m_res);
}

TEST_F(sys_call_test, markers_15)
{
	sinsp_markerparser p(NULL);

	char doc[] = "[\">\", 123, [\"mysql\"], [{\"argname1\":\"argval1\"}, {\"argname1\":\"argval1\"]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_markerparser::RES_FAILED, p.m_res);
}

TEST_F(sys_call_test, markers_16)
{
	sinsp_markerparser p(NULL);

	char doc[] = "[\">\", 123, [\"mysql\"], [{\"argname1\":\"argval1\"}, \"argname1\":\"argval1\"]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_markerparser::RES_FAILED, p.m_res);
}

TEST_F(sys_call_test, markers_17)
{
	sinsp_markerparser p(NULL);

	char doc[] = "[\">\", 123, [mysql], [{\"argname1\":\"argval1\"}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_markerparser::RES_FAILED, p.m_res);
}

TEST_F(sys_call_test, markers_18)
{
	sinsp_markerparser p(NULL);

	char doc[] = "[\">\", 123, [\"mysql\"], [{argname1:\"argval1\"}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_markerparser::RES_FAILED, p.m_res);
}

TEST_F(sys_call_test, markers_19)
{
	sinsp_markerparser p(NULL);

	char doc[] = "[\">\", 123, [\"mysql\"], [{\"argname1\":argval1}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_markerparser::RES_FAILED, p.m_res);
}

TEST_F(sys_call_test, markers_20)
{
	sinsp_markerparser p(NULL);

	char doc[] = "[\">\", 123, [\"mysql\"], [{\"argname1\":\"argval1\"}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_markerparser::RES_OK, p.m_res);
}

TEST_F(sys_call_test, markers_21)
{
	sinsp_markerparser p(NULL);

	char doc[] = "[\">\", 123, [\"mysql\"], [{\"argname1\":\"argval1\"}, {\"argname1\":\"argval1\"}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_markerparser::RES_OK, p.m_res);
}

TEST_F(sys_call_test, markers_22)
{
	sinsp_markerparser p(NULL);

	char doc[] = "[\">\", 123, [\"mysql\"], [{\"argname1\":\"argval1\"} {\"argname1\":\"argval1\"}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_markerparser::RES_FAILED, p.m_res);
}

TEST_F(sys_call_test, markers_23)
{
	sinsp_markerparser p(NULL);

	char doc[] = "[\">\", 123, [\"mysql\"], [{\"argname1\":\"argval1\"}{\"argname1\":\"argval1\"}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_markerparser::RES_FAILED, p.m_res);
}

TEST_F(sys_call_test, markers_24)
{
	sinsp_markerparser p(NULL);

	char doc[] = "[\">\", 12, [\"mysql\"], []]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_markerparser::RES_OK, p.m_res);
	EXPECT_EQ(">", string(p.m_type_str));
	EXPECT_EQ(12, (int)p.m_id);
	EXPECT_EQ(1, (int)p.m_tags.size());
	EXPECT_EQ(0, (int)p.m_argnames.size());
	EXPECT_EQ(0, (int)p.m_argvals.size());
}

TEST_F(sys_call_test, markers_25)
{
	sinsp_markerparser p(NULL);

	char doc[] = "[\">\", 12, [], [{\"argname1\":\"argval1\"}, {\"argname2\":\"argval2\"}]]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_markerparser::RES_OK, p.m_res);
	EXPECT_EQ(">", string(p.m_type_str));
	EXPECT_EQ(12, (int)p.m_id);
	EXPECT_EQ(0, (int)p.m_tags.size());
	EXPECT_EQ(2, (int)p.m_argnames.size());
	EXPECT_EQ(2, (int)p.m_argvals.size());
}

TEST_F(sys_call_test, markers_26)
{
	sinsp_markerparser p(NULL);

	char doc[] = "[\">\", 12, [], []]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_markerparser::RES_OK, p.m_res);
	EXPECT_EQ(">", string(p.m_type_str));
	EXPECT_EQ(12, (int)p.m_id);
	EXPECT_EQ(0, (int)p.m_tags.size());
	EXPECT_EQ(0, (int)p.m_argnames.size());
	EXPECT_EQ(0, (int)p.m_argvals.size());
}

TEST_F(sys_call_test, markers_27)
{
	sinsp_markerparser p(NULL);

	char doc[] = "        [\">\", 12, [], []]]        ";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_markerparser::RES_OK, p.m_res);
	EXPECT_EQ(">", string(p.m_type_str));
	EXPECT_EQ(12, (int)p.m_id);
	EXPECT_EQ(0, (int)p.m_tags.size());
	EXPECT_EQ(0, (int)p.m_argnames.size());
	EXPECT_EQ(0, (int)p.m_argvals.size());
}

TEST_F(sys_call_test, markers_28)
{
	sinsp_markerparser p(NULL);

	char doc[] = "        [\">\"             ,      12  , [], [  ]    ]         ]        ";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_markerparser::RES_OK, p.m_res);
	EXPECT_EQ(">", string(p.m_type_str));
	EXPECT_EQ(12, (int)p.m_id);
	EXPECT_EQ(0, (int)p.m_tags.size());
	EXPECT_EQ(0, (int)p.m_argnames.size());
	EXPECT_EQ(0, (int)p.m_argvals.size());
}

TEST_F(sys_call_test, markers_29)
{
	sinsp_markerparser p(NULL);

	char doc[] = "[\">\", ";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_markerparser::RES_TRUNCATED, p.m_res);
}

TEST_F(sys_call_test, markers_31)
{
	sinsp_markerparser p(NULL);

	char doc1[] = "[\">\", 12435, [\"mysql\", \"query\", \"in";
	char doc2[] = "it\"], [{\"argname1\":\"argval1\"}, {\"argname2\":\"argval2\"";
	char doc3[] = "}, {\"argname3\":\"argval3\"}]]";

	p.process_event_data(doc1, sizeof(doc1) - 1, 10);
	EXPECT_EQ(sinsp_markerparser::RES_TRUNCATED, p.m_res);

	p.process_event_data(doc2, sizeof(doc2) - 1, 10);
	EXPECT_EQ(sinsp_markerparser::RES_TRUNCATED, p.m_res);

	p.process_event_data(doc3, sizeof(doc3) - 1, 10);

	EXPECT_EQ(sinsp_markerparser::RES_OK, p.m_res);
	EXPECT_EQ(">", string(p.m_type_str));
	EXPECT_EQ(12435, (int)p.m_id);
	EXPECT_EQ(3, (int)p.m_tags.size());
	EXPECT_EQ(3, (int)p.m_argnames.size());
	EXPECT_EQ(3, (int)p.m_argvals.size());
}

TEST_F(sys_call_test, markers_32)
{
	sinsp_markerparser p(NULL);

	char doc1[] = "[\">\", 12435, [\"mysql\", \"query\"";
	char doc2[] = ", \"init\"], [{\"argname1\":\"argval1\"}, {\"argname2\":";
	char doc3[] = "\"argval2\"}, {\"argname3\":\"argval3\"}]]";

	p.process_event_data(doc1, sizeof(doc1) - 1, 10);
	EXPECT_EQ(sinsp_markerparser::RES_TRUNCATED, p.m_res);

	p.process_event_data(doc2, sizeof(doc2) - 1, 10);
	EXPECT_EQ(sinsp_markerparser::RES_TRUNCATED, p.m_res);

	p.process_event_data(doc3, sizeof(doc3) - 1, 10);

	EXPECT_EQ(sinsp_markerparser::RES_OK, p.m_res);
	EXPECT_EQ(">", string(p.m_type_str));
	EXPECT_EQ(12435, (int)p.m_id);
	EXPECT_EQ(3, (int)p.m_tags.size());
	EXPECT_EQ(3, (int)p.m_argnames.size());
	EXPECT_EQ(3, (int)p.m_argvals.size());
}

TEST_F(sys_call_test, markers_33)
{
	sinsp_markerparser p(NULL);

	char doc1[] = "[\">\", 12435, [\"mys";
	char doc2[] = "ql\", \"query\", \"init\"], [{\"argname1\":\"argval1\"}";
	char doc3[] = ", {\"argname2\":\"argval2\"}, {\"argname3\":\"argval3\"}]]";

	p.process_event_data(doc1, sizeof(doc1) - 1, 10);
	EXPECT_EQ(sinsp_markerparser::RES_TRUNCATED, p.m_res);

	p.process_event_data(doc2, sizeof(doc2) - 1, 10);
	EXPECT_EQ(sinsp_markerparser::RES_TRUNCATED, p.m_res);

	p.process_event_data(doc3, sizeof(doc3) - 1, 10);

	EXPECT_EQ(sinsp_markerparser::RES_OK, p.m_res);
	EXPECT_EQ(">", string(p.m_type_str));
	EXPECT_EQ(12435, (int)p.m_id);
	EXPECT_EQ(3, (int)p.m_tags.size());
	EXPECT_EQ(3, (int)p.m_argnames.size());
	EXPECT_EQ(3, (int)p.m_argvals.size());
}

TEST_F(sys_call_test, markers_34)
{
	sinsp_markerparser p(NULL);

	char doc1[] = "[\">\", 12435,";
	char doc2[] = " [\"mysql\", \"query\", ";
	char doc3[] = "\"init\"], [{\"argname1\":\"argval1\"}, {\"argname2\":\"argval2\"}, {\"argname3\":\"argval3\"}]]";

	p.process_event_data(doc1, sizeof(doc1) - 1, 10);
	EXPECT_EQ(sinsp_markerparser::RES_TRUNCATED, p.m_res);

	p.process_event_data(doc2, sizeof(doc2) - 1, 10);
	EXPECT_EQ(sinsp_markerparser::RES_TRUNCATED, p.m_res);

	p.process_event_data(doc3, sizeof(doc3) - 1, 10);

	EXPECT_EQ(sinsp_markerparser::RES_OK, p.m_res);
	EXPECT_EQ(">", string(p.m_type_str));
	EXPECT_EQ(12435, (int)p.m_id);
	EXPECT_EQ(3, (int)p.m_tags.size());
	EXPECT_EQ(3, (int)p.m_argnames.size());
	EXPECT_EQ(3, (int)p.m_argvals.size());
}

TEST_F(sys_call_test, markers_35)
{
	sinsp_markerparser p(NULL);

	char doc1[] = "[\">\", 12435";
	char doc2[] = ", [\"mysql\", \"query\",";
	char doc3[] = " \"init\"], [{\"argname1\":\"argval1\"}, {\"argname2\":\"argval2\"}, {\"argname3\":\"argval3\"}]]";

	p.process_event_data(doc1, sizeof(doc1) - 1, 10);
	EXPECT_EQ(sinsp_markerparser::RES_TRUNCATED, p.m_res);

	p.process_event_data(doc2, sizeof(doc2) - 1, 10);
	EXPECT_EQ(sinsp_markerparser::RES_TRUNCATED, p.m_res);

	p.process_event_data(doc3, sizeof(doc3) - 1, 10);

	EXPECT_EQ(sinsp_markerparser::RES_OK, p.m_res);
	EXPECT_EQ(">", string(p.m_type_str));
	EXPECT_EQ(12435, (int)p.m_id);
	EXPECT_EQ(3, (int)p.m_tags.size());
	EXPECT_EQ(3, (int)p.m_argnames.size());
	EXPECT_EQ(3, (int)p.m_argvals.size());
}

TEST_F(sys_call_test, markers_39)
{
	sinsp_markerparser p(NULL);

	char doc1[] = "";
	char doc2[] = "";
	char doc3[] = "[\">\", 12435, [\"mysql\", \"query\", \"init\"], [{\"argname1\":\"argval1\"}, {\"argname2\":\"argval2\"}, {\"argname3\":\"argval3\"}]]";

	p.process_event_data(doc1, sizeof(doc1) - 1, 10);
	EXPECT_EQ(sinsp_markerparser::RES_FAILED, p.m_res);

	p.process_event_data(doc2, sizeof(doc2) - 1, 10);
	EXPECT_EQ(sinsp_markerparser::RES_FAILED, p.m_res);

	p.process_event_data(doc3, sizeof(doc3) - 1, 10);

	EXPECT_EQ(sinsp_markerparser::RES_OK, p.m_res);
	EXPECT_EQ(">", string(p.m_type_str));
	EXPECT_EQ(12435, (int)p.m_id);
	EXPECT_EQ(3, (int)p.m_tags.size());
	EXPECT_EQ(3, (int)p.m_argnames.size());
	EXPECT_EQ(3, (int)p.m_argvals.size());
}

TEST_F(sys_call_test, markers_40)
{
	sinsp_markerparser p(NULL);
	char tb[2];
	tb[1] = 0;
	uint32_t k;

	char doc[] = "[\">\", 12435, [\"mysql\", \"query\", \"init\"], [{\"argname1\":\"argval1\"}, {\"argname2\":\"argval2\"}, {\"argname3\":\"argval3\"}]]";

	for(k = 0; k < sizeof(doc) - 2; k++)
	{
		tb[0] = doc[k];
		p.process_event_data(tb, 1, 10);
		EXPECT_EQ(sinsp_markerparser::RES_TRUNCATED, p.m_res);
	}

	tb[0] = doc[k];
	p.process_event_data(tb, 1, 10);

	EXPECT_EQ(sinsp_markerparser::RES_OK, p.m_res);
	EXPECT_EQ(">", string(p.m_type_str));
	EXPECT_EQ(12435, (int)p.m_id);
	EXPECT_EQ(3, (int)p.m_tags.size());
	EXPECT_EQ(3, (int)p.m_argnames.size());
	EXPECT_EQ(3, (int)p.m_argvals.size());
}

TEST_F(sys_call_test, markers_41)
{
	sinsp_markerparser p(NULL);

	char doc[] = "[\"\\\">\", 12435, [\"my\\\"\\\"sql\", \"query\", \"init\"], [{\"argname1\":\"argval1\"}, {\"argname2\":\"argval2\"}, {\"argname3\":\"argval3\"}]]";
	char buffer[sizeof(doc)];
	memcpy(buffer, doc, sizeof(doc));

	p.process_event_data(buffer, sizeof(doc) - 1, 10);

	EXPECT_EQ(sinsp_markerparser::RES_OK, p.m_res);
	EXPECT_EQ("\\\">", string(p.m_type_str));
	EXPECT_EQ(12435, (int)p.m_id);
	EXPECT_EQ(3, (int)p.m_tags.size());
	EXPECT_EQ(3, (int)p.m_argnames.size());
	EXPECT_EQ(3, (int)p.m_argvals.size());
}

#endif // 0