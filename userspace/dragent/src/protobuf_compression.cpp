#include "protobuf_compression.h"
#include "protocol_handler.h"

bool null_protobuf_compressor::compress(const google::protobuf::MessageLite& message,
                                        google::protobuf::io::StringOutputStream& string_output)
{
	bool res = message.SerializeToZeroCopyStream(&string_output);
	if (!res)
	{
		ASSERT(false);
		g_log->error("Error serializing uncompressed protobuf");
	}

	return res;
}

gzip_protobuf_compressor::gzip_protobuf_compressor(int compression_level)
    : protobuf_compressor(protocol_compression_method::GZIP)
{
	if (compression_level > Z_BEST_COMPRESSION)
	{
		g_log->warning("Invalid gzip compression level: " + compression_level);
		compression_level = Z_BEST_COMPRESSION;
	}
	else if (compression_level < Z_DEFAULT_COMPRESSION)
	{
		g_log->warning("Invalid gzip compression level: " + compression_level);
		compression_level = Z_DEFAULT_COMPRESSION;
	}
	m_compression_level = compression_level;
}

bool gzip_protobuf_compressor::compress(const google::protobuf::MessageLite& message,
                                        google::protobuf::io::StringOutputStream& string_output)
{
	google::protobuf::io::GzipOutputStream::Options opts;

	opts.compression_level = m_compression_level;

	google::protobuf::io::GzipOutputStream gzip_output(&string_output, opts);

	bool res = message.SerializeToZeroCopyStream(&gzip_output);
	if (!res)
	{
		ASSERT(false);
		g_log->error("Error gzip serializing protobuf");
		return res;
	}

	res = gzip_output.Close();
	if (!res)
	{
		ASSERT(false);
		g_log->error("Error closing GzipOutputStream");
		return res;
	}

	return res;
}

std::shared_ptr<protobuf_compressor> protobuf_compressor_factory::get(
    protocol_compression_method compression)
{
	switch (compression)
	{
	case protocol_compression_method::NONE:
		return null_protobuf_compressor::get();
	case protocol_compression_method::GZIP:
		return gzip_protobuf_compressor::get(-1);
	}
	return nullptr;
}

std::shared_ptr<protobuf_compressor> protobuf_compressor_factory::get_default_compressor()
{
	return get(get_default());
}

protocol_compression_method protobuf_compressor_factory::get_default()
{
	return protocol_handler::c_compression_enabled.get_value()
	           ? protocol_compression_method::GZIP
	           : protocol_compression_method::NONE;
}
