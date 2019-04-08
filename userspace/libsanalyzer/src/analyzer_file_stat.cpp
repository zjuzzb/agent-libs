#include "analyzer_file_stat.h"

#include "draios.pb.h"

void analyzer_file_stat::to_protobuf(draiosproto::file_stat *protobuf) const
{
	protobuf->set_bytes(m_bytes);
	protobuf->set_time_ns(m_time_ns);
	protobuf->set_open_count(m_open_count);
	protobuf->set_errors(m_errors);
}
