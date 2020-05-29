#include "running_state.h"
#include <gtest.h>

namespace test_helpers
{

/**
 * Resets dragent's running state after each test
 */
class running_state_fixture : public testing::Test
{
public: 
	running_state_fixture() 
	{
	} 

	void SetUp() override
	{
		// Ambitious developers would change the running_state 
		// instance to a pointer that had to be initialized here 
		// (and at dragent startup). That would force anyone 
		// whose test touched the running_state data to use 
		// this fixture and guarantee cleanup.
	}

	void TearDown() override
	{
		dragent::running_state::instance().reset_for_test();
	}
};

}
