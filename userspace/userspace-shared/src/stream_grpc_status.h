#pragma once

#ifndef CYGWING_AGENT
#ifndef _WIN32

struct streaming_grpc {
	enum Status {
		OK = 0,
		ERROR,
		SHUTDOWN
	};
};

#endif  // _WIN32
#endif  // CYGWING_AGENT
