#include <fcntl.h>
#include <memory>
#include <unistd.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/text_format.h>
#include <grpc++/server.h>
#include <grpc++/server_builder.h>
#include <grpc++/server_context.h>
#include "cri.grpc.pb.h"

using namespace runtime::v1alpha2;

class FakeCRIServer final : public runtime::v1alpha2::RuntimeService::Service {
public:
	FakeCRIServer(int delay_us, ContainerStatusResponse&& cs, PodSandboxStatusResponse&& ps, const std::string& runtime_name) :
		m_delay_us(delay_us),
		m_container_status_response(cs),
		m_pod_sandbox_status_response(ps),
		m_runtime_name(runtime_name)
	{}

	grpc::Status ContainerStatus(grpc::ServerContext* context,
				     const ContainerStatusRequest* req,
				     ContainerStatusResponse* resp)
	{
		usleep(m_delay_us);
		resp->CopyFrom(m_container_status_response);
		resp->mutable_status()->set_id(req->container_id());
		return grpc::Status::OK;
	}


	grpc::Status PodSandboxStatus(grpc::ServerContext* context,
		const PodSandboxStatusRequest* req,
		PodSandboxStatusResponse* resp)
	{
		usleep(m_delay_us);
		resp->CopyFrom(m_pod_sandbox_status_response);
		resp->mutable_status()->set_id(req->pod_sandbox_id());
		return grpc::Status::OK;
	}

	grpc::Status Version(grpc::ServerContext* context,
		const VersionRequest* req,
		VersionResponse* resp)
	{
		resp->set_version("0.1.0");
		resp->set_runtime_name(m_runtime_name);
		resp->set_runtime_version("1.1.2");
		resp->set_runtime_api_version("v1alpha2");
		return grpc::Status::OK;
	}
private:
	int m_delay_us;
	ContainerStatusResponse m_container_status_response;
	PodSandboxStatusResponse m_pod_sandbox_status_response;
	std::string m_runtime_name;
};

class FakeCRIImageServer final : public runtime::v1alpha2::ImageService::Service {
public:
	FakeCRIImageServer(ListImagesResponse&& is) :
		m_list_images_response(is) {}

	grpc::Status ListImages(grpc::ServerContext *context,
				     const ListImagesRequest *req,
				     ListImagesResponse *resp)
	{
		resp->CopyFrom(m_list_images_response);
		return grpc::Status::OK;
	}
private:
	ListImagesResponse m_list_images_response;
};


int main(int argc, char** argv)
{
	google::protobuf::io::FileOutputStream pb_stdout(1);
	int delay_us = 0;

	if (argc < 3)
	{
		fprintf(stderr, "Usage: fake_cri [--nodelay|--slow|--veryslow] listen_addr pb_file_prefix [runtime_name]\n");
		return 1;
	}

	if(argv[1] == std::string("--nodelay"))
	{
		// no delay, the default
		delay_us = 0;
		argv++;
	}
	else if(argv[1] == std::string("--slow"))
	{
		// 500 ms is slow but not slow enough to trigger the timeout
		delay_us = 500000;
		argv++;
	}
	else if(argv[1] == std::string("--veryslow"))
	{
		// 1200 ms is beyond the default 1 sec timeout so queries will fail
		delay_us = 1200000;
		argv++;
	}

	const char* addr = argv[1];
	const std::string pb_prefix(argv[2]);
	const std::string runtime(argc > 3 ? argv[3]: "containerd");

	ContainerStatusResponse cs;
	{
		const std::string path = pb_prefix + "_container.pb";
		int fd = open(path.c_str(), O_RDONLY);
		google::protobuf::io::FileInputStream fs(fd);
		google::protobuf::TextFormat::Parse(&fs, &cs);
		close(fd);
	}

	PodSandboxStatusResponse ps;
	{
		const std::string path = pb_prefix + "_pod.pb";
		int fd = open(path.c_str(), O_RDONLY);
		google::protobuf::io::FileInputStream fs(fd);
		google::protobuf::TextFormat::Parse(&fs, &ps);
		close(fd);
	}

	ListImagesResponse is;
	{
		const std::string path = pb_prefix + "_images.pb";
		int fd = open(path.c_str(), O_RDONLY);
		if (fd >= 0)
		{
			google::protobuf::io::FileInputStream fs(fd);
			google::protobuf::TextFormat::Parse(&fs, &is);
			close(fd);
		}
	}

	FakeCRIServer service(delay_us, std::move(cs), std::move(ps), runtime);
	FakeCRIImageServer image_service(std::move(is));

	grpc::ServerBuilder builder;
	builder.AddListeningPort(addr, grpc::InsecureServerCredentials());
	builder.RegisterService(&service);
	builder.RegisterService(&image_service);
	std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
	server->Wait();

	return 0;
}