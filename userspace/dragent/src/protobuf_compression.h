#pragma once

#include "protocol.h"
#include "zlib.h"
#include "common_logger.h"
#include <memory>

class protobuf_compressor {
public:
	virtual ~protobuf_compressor() = default;

	virtual bool compress(const google::protobuf::MessageLite& message,
	                      google::protobuf::io::StringOutputStream& string_output) = 0;
};

/**
 * Does no compression, just serializes the protobuf to the output stream
 */
class null_protobuf_compressor : public protobuf_compressor {
public:
	bool compress(const google::protobuf::MessageLite& message,
	              google::protobuf::io::StringOutputStream& string_output) override
	{
		bool res = message.SerializeToZeroCopyStream(&string_output);
		if (!res)
		{
			ASSERT(false);
			g_log->error("Error serializing uncompressed protobuf");
		}

		return res;
	}

	static std::shared_ptr<protobuf_compressor> get()
	{
		return std::shared_ptr<protobuf_compressor>(new null_protobuf_compressor);
	}
};

/**
 * Gzips the given protobuf and writes it to the given output stream.
 */
class gzip_protobuf_compressor : public protobuf_compressor {
public:
	gzip_protobuf_compressor(int compression_level)
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

	bool compress(const google::protobuf::MessageLite& message,
	              google::protobuf::io::StringOutputStream& string_output) override
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

	int get_compression_level() const
	{
		return m_compression_level;
	}

	static std::shared_ptr<protobuf_compressor> get(int compression_level)
	{
		return std::shared_ptr<protobuf_compressor>(new gzip_protobuf_compressor(compression_level));
	}

private:
	int m_compression_level;
};
