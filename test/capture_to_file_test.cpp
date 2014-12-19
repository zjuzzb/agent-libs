#include <sinsp.h>
#include "sys_call_test.h"
#include <gtest.h>

TEST(capture_on_file,can_consume_a_capture_file)
{
	sinsp inspector;
	sinsp_evt *event;

	inspector.open();
	inspector.set_debug_mode(true);
	inspector.autodump_start("/tmp/can_consume_a_capture_file.scap", false);
	for(int j=0; j < 1000;)
	{
		int32_t res = inspector.next(&event);

		if(res == SCAP_TIMEOUT)
		{
			continue;
		}

		j++;
		ASSERT_EQ(SCAP_SUCCESS, res);
	}
	inspector.stop_capture();
	inspector.close();
	cerr << "stopped capture" << endl;
	inspector.open("/tmp/can_consume_a_capture_file.scap");
	for(int j=0; j < 1000; j++)
	{
		int32_t res = inspector.next(&event);
		ASSERT_EQ(SCAP_SUCCESS, res);
	}

	ASSERT_EQ(SCAP_EOF, inspector.next(&event));
}