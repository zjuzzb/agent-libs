#include <fcntl.h>
#include <memory>
#include <string>
#include <unistd.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/text_format.h>
#include <grpc++/server.h>
#include <grpc++/server_builder.h>
#include <grpc++/server_context.h>
#include "sdc_internal.grpc.pb.h"

using namespace sdc_internal;

class TestGRPCServer final : public CoInterface::Service {
public:
	grpc::Status PerformPing(grpc::ServerContext* context, const ping* req, pong* resp) override
	{
		uint64_t token = req->token();
		resp->set_token(token);
		resp->set_pid(getpid());
		resp->set_memory_used(10000);

		sleep(token >> 16);
		return grpc::Status::OK;
	}

	grpc::Status PerformOrchestratorEventsStream(
		grpc::ServerContext* context,
		const orchestrator_events_stream_command* req,
		grpc::ServerWriter<array_congroup_update_event>* writer) override
	{
		for(int i=0; i<10; ++i)
		{
			struct timespec ts = {};
			ts.tv_nsec = 500 * 1000000; // 500 ms

			array_congroup_update_event resp;
			writer->Write(resp);
			nanosleep(&ts, nullptr);
		}
		return grpc::Status::OK;
	}
};

int main(int argc, char** argv)
{
	if (argc < 2)
	{
		fprintf(stderr, "Usage: grpc_test_server listen_addr\n");
		return 1;
	}

	const char* addr = argv[1];
	TestGRPCServer service;

	grpc::ServerBuilder builder;
	builder.AddListeningPort(addr, grpc::InsecureServerCredentials());
	builder.RegisterService(&service);
	std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
	server->Wait();

	return 0;
}