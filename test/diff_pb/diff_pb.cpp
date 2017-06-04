#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <sstream>

#include <google/protobuf/text_format.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/util/message_differencer.h>

#include "metrics_list.pb.h"

using namespace std;
using namespace google::protobuf;

static std::vector<string> split_to_vector(const string &input, const string &delim)
{
	std::vector<string> parts;
	std::istringstream ss(input);
	std::string token;

	while(std::getline(ss, token, '.')) {
		parts.push_back(token);
	}

	return parts;
}

// Traverse a nested message to find a given field.
static const FieldDescriptor* FindField(const Message& message, const string& field_name)
{
	std::vector<string> field_path;

	field_path = split_to_vector(field_name, ".");

	const Descriptor* descriptor = message.GetDescriptor();
	const FieldDescriptor* field = NULL;

	for (uint32_t i = 0; i < field_path.size(); i++) {
		field = descriptor->FindFieldByName(field_path[i]);
		descriptor = field->message_type();
	}
	return field;
}

// A subclass of StreamReporter that suppresses ReportMoved and
// ReportIgnored. We don't care if items move positions, only if their
// contents change, and we don't care that they were ignored.
class IgnoreMovedReporter : public util::MessageDifferencer::StreamReporter
{
public:
	IgnoreMovedReporter(io::ZeroCopyOutputStream * output) :
		util::MessageDifferencer::StreamReporter(output) {};
	IgnoreMovedReporter(io::Printer * printer) :
		util::MessageDifferencer::StreamReporter(printer) {};
	virtual ~IgnoreMovedReporter() {};
	virtual void ReportMoved(const Message & message1, const Message & message2,
				 const std::vector< util::MessageDifferencer::SpecificField > & field_path) {};
	virtual void ReportIgnored(const Message & message1, const Message & message2,
				   const std::vector< util::MessageDifferencer::SpecificField > & field_path) {};
};

static int read_pb(const char *filename, draiosproto_w_metrics_list::metrics_list *m)
{
	int fd = open(filename, O_RDONLY);
	io::FileInputStream fstream(fd);
	if (!TextFormat::Parse(&fstream, m)) {
		cerr << "Failed to parse " << filename << endl;
		return -1;
	}
	close(fd);

	return 0;
}

int main(int argc, char **argv)
{
	int rc;

	// Verify that the version of the library that we linked against is
	// compatible with the version of the headers we compiled against.
	GOOGLE_PROTOBUF_VERIFY_VERSION;

	if (argc != 3) {
		cerr << "Usage:  " << argv[0] << " this-pb-file that-pb-file" << endl;
		return -1;
	}

	draiosproto_w_metrics_list::metrics_list m1, m2;
	if((rc = read_pb(argv[1], &m1)) != 0 ||
	   (rc = read_pb(argv[2], &m2)) != 0)
	{
		return rc;
	}

	util::MessageDifferencer md;

	// Allow metrics.programs values to be reordered, using
	// metrics.programs.pids as a unique key for the set of
	// programs.
	md.TreatAsMap(FindField(m1, "metrics.programs"),
		      FindField(m1, "metrics.programs.pids"));

	md.TreatAsMap(FindField(m1, "metrics.protos.mysql.client_queries"),
				  FindField(m1, "metrics.protos.mysql.client_queries.name"));
	md.TreatAsMap(FindField(m1, "metrics.protos.mysql.client_query_types"),
				  FindField(m1, "metrics.protos.mysql.client_query_types.type"));
	md.TreatAsMap(FindField(m1, "metrics.protos.mysql.client_tables"),
				  FindField(m1, "metrics.protos.mysql.client_tables.name"));

	md.TreatAsMap(FindField(m1, "metrics.protos.mysql.server_queries"),
				  FindField(m1, "metrics.protos.mysql.server_queries.name"));
	md.TreatAsMap(FindField(m1, "metrics.protos.mysql.server_query_types"),
				  FindField(m1, "metrics.protos.mysql.server_query_types.type"));
	md.TreatAsMap(FindField(m1, "metrics.protos.mysql.server_tables"),
				  FindField(m1, "metrics.protos.mysql.server_tables.name"));

	md.TreatAsMap(FindField(m1, "metrics.protos.http.client_urls"),
				  FindField(m1, "metrics.protos.http.client_urls.url"));
	md.TreatAsMap(FindField(m1, "metrics.protos.http.client_status_codes"),
				  FindField(m1, "metrics.protos.http.client_status_codes.status_code"));
	md.TreatAsMap(FindField(m1, "metrics.protos.http.server_urls"),
				  FindField(m1, "metrics.protos.http.server_urls.url"));
	md.TreatAsMap(FindField(m1, "metrics.protos.http.server_status_codes"),
				  FindField(m1, "metrics.protos.http.server_status_codes.status_code"));

	md.IgnoreField(FindField(m1, "metrics.hostinfo.system_load_1"));
	md.IgnoreField(FindField(m1, "metrics.hostinfo.system_load_5"));
	md.IgnoreField(FindField(m1, "metrics.hostinfo.system_load_15"));

	// This is its own block to force the IgnoreMovedReporter to
	// flush everything to diffs.
	string diffs;
	{
		io::StringOutputStream output_stream(&diffs);
		IgnoreMovedReporter reporter(&output_stream);
		md.ReportDifferencesTo(&reporter);

		if (md.Compare(m1, m2))
		{
			cerr << "Protobufs Equal" << endl;
			return 0;
		}
	}

	cerr << "Protobufs Differ. Differences:" << endl;
	cerr << diffs;
	return 1;
}
