#include <benchmark/benchmark.h>

#include <fcntl.h>
#include <fstream>
#include <sys/stat.h>

#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/io/gzip_stream.h>

#include "main.h"
#include "protocol.h"
#include "draios.pb.h"

class ProtobufSerializationBM : public ::benchmark::Fixture
{
public:
	void SetUp(::benchmark::State& state)
	{
		std::ifstream fstream("resources/benchmark.dam", std::ios::ate | std::ios::binary);
		dam_size = fstream.tellg() - 2L;
		fstream.seekg(2, std::ios::beg);
		if(!fstream)
		{
			state.SkipWithError("Failed to open dam file");
		}
		if(!msg.ParseFromIstream(&fstream))
		{
			state.SkipWithError("Failed to read dam file");
		}

		devnull_fd = open("/dev/null", O_WRONLY);
		if (devnull_fd == -1)
		{
			state.SkipWithError("Failed to open /dev/null");
		}
	}

	void TearDown(::benchmark::State& state)
	{
		close(devnull_fd);
	}

	draiosproto::metrics msg;
	int devnull_fd;
	ssize_t dam_size;
};


BENCHMARK_DEFINE_F(ProtobufSerializationBM, ProtobufUncompressedSerialize)(benchmark::State& st) {
	for(auto _ : st)
	{
		google::protobuf::io::FileOutputStream file_stream(devnull_fd);
		benchmark::DoNotOptimize(msg.SerializeToZeroCopyStream(&file_stream));
	}
	st.SetBytesProcessed(int64_t(st.iterations()) * dam_size);
	st.counters.insert({{"dam_size", dam_size}});
}
BENCHMARK_REGISTER_F(ProtobufSerializationBM, ProtobufUncompressedSerialize);


BENCHMARK_DEFINE_F(ProtobufSerializationBM, ProtobufCompressedSerialize)(benchmark::State& st) {
	for(auto _ : st)
	{
		google::protobuf::io::FileOutputStream file_stream(devnull_fd);
		google::protobuf::io::GzipOutputStream gzip_stream(&file_stream);

		benchmark::DoNotOptimize(msg.SerializeToZeroCopyStream(&gzip_stream));
	}
	st.SetBytesProcessed(int64_t(st.iterations()) * dam_size);
	st.counters.insert({{"dam_size", dam_size}});
}
BENCHMARK_REGISTER_F(ProtobufSerializationBM, ProtobufCompressedSerialize);

BENCHMARK_DEFINE_F(ProtobufSerializationBM, DragentUncompressedSerialize)(benchmark::State& st) {
	for(auto _ : st)
	{
		benchmark::DoNotOptimize(dragent_protocol::message_to_buffer(0, 1, msg, false));
	}
	st.SetBytesProcessed(int64_t(st.iterations()) * dam_size);
	st.counters.insert({{"dam_size", dam_size}});
}
BENCHMARK_REGISTER_F(ProtobufSerializationBM, DragentUncompressedSerialize);

BENCHMARK_DEFINE_F(ProtobufSerializationBM, DragentCompressedSerialize)(benchmark::State& st) {
	for(auto _ : st)
	{
		benchmark::DoNotOptimize(dragent_protocol::message_to_buffer(0, 1, msg, true));
	}
	st.SetBytesProcessed(int64_t(st.iterations()) * dam_size);
	st.counters.insert({{"dam_size", dam_size}});
}
BENCHMARK_REGISTER_F(ProtobufSerializationBM, DragentCompressedSerialize);
