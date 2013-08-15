#include <sinsp.h>
#include "sys_call_test.h"
#include <gtest.h>

TEST(capture_on_file,can_consume_a_capture_file)
{
	sinsp inspector;
	sinsp_evt *event;

	inspector.open();
	inspector.start_dump("/tmp/can_consume_a_capture_file.scap");
	for(int j=0; j < 1000; j++)
	{
		ASSERT_EQ(SCAP_SUCCESS,inspector.next(&event));
	}
	inspector.stop_capture();
	inspector.close();
	cerr << "stopped capture" << endl;
	inspector.open("/tmp/can_consume_a_capture_file.scap");
	for(int j=0; j < 1000; j++)
	{
		ASSERT_EQ(SCAP_SUCCESS,inspector.next(&event));
	}
	ASSERT_EQ(SCAP_EOF, inspector.next(&event));
}