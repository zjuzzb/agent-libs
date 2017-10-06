// Replacements for macros available via glog/logging.h

#ifdef ENABLE_TDIGEST_LOGS

#include <iostream>
#define LOG(_lvl_)	std::cout << std::endl
#define DLOG(_lvl_)	std::cout << std::endl

#else // ENABLE_TDIGEST_LOGS

#include <fstream>

static
std::ofstream& nullStream() {
	static std::ofstream _nullStream;
	return _nullStream;
}
#define DLOG(_lvl_)	nullStream()
#define LOG(_lvl_)	nullStream()

#endif // ENABLE_TDIGEST_LOGS

#define CHECK_OP(_op_, _val1_, _val2_)	do {\
	if (!(_val1_ _op_ _val2_)) {\
		throw std::runtime_error(#_val1_ " is not " #_op_ " " #_val2_);\
	}\
}while(false)

#define CHECK_EQ(_val1, _val2) CHECK_OP(==, _val1, _val2)
#define CHECK_NE(_val1, _val2) CHECK_OP(!=, _val1, _val2)
#define CHECK_LE(_val1, _val2) CHECK_OP(<=, _val1, _val2)
#define CHECK_LT(_val1, _val2) CHECK_OP(< , _val1, _val2)
#define CHECK_GE(_val1, _val2) CHECK_OP(>=, _val1, _val2)
#define CHECK_GT(_val1, _val2) CHECK_OP(> , _val1, _val2)
