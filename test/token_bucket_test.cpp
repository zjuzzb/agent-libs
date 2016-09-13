#include <gtest.h>

#include "token_bucket.h"

TEST(token_bucket_test, all)
{
	token_bucket b;

	b.init(1, 10);

	// Should be able to claim exactly 10 tokens.
	for (uint32_t i=0; i<10; i++)
	{
		bool ret = b.claim();
		ASSERT_TRUE(ret);
	}
	ASSERT_FALSE(b.claim());

	//
	// Not being horribly strict here--wait 2 seconds and ensure
	// that you can claim more than 1 token.
	sleep(2);

	for (uint32_t i=0; i<2; i++)
	{
		ASSERT_TRUE(b.claim());
	}
}
