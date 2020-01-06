#pragma once

#include "protocol.h"
#include "zlib.h"
#include "common_logger.h"
#include <memory>


class protobuf_compressor {
public:
	protobuf_compressor(protocol_compression_method compression_method) :
	    m_compression_method(compression_method)
	{}
	virtual ~protobuf_compressor() = default;

	virtual bool compress(const google::protobuf::MessageLite& message,
	                      google::protobuf::io::StringOutputStream& string_output) = 0;

	protocol_compression_method get_compression_method() { return m_compression_method; }

private:
	protocol_compression_method m_compression_method;
};

/**
 * Does no compression, just serializes the protobuf to the output stream
 */
class null_protobuf_compressor : public protobuf_compressor {
public:
	null_protobuf_compressor() :
	    protobuf_compressor(protocol_compression_method::NONE)
	{}

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
	gzip_protobuf_compressor(int compression_level) :
	    protobuf_compressor(protocol_compression_method::GZIP)
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

/**
 * Builds the correct protobuf compressor given the compression method.
 */
class protobuf_compressor_factory
{
public:
	/**
	 * Builds a protobuf_compressor object based on the given compression method.
	 */
	static std::shared_ptr<protobuf_compressor> get(protocol_compression_method compression)
	{
		if (compression == protocol_compression_method::NONE)
		{
			return null_protobuf_compressor::get();
		}
		return gzip_protobuf_compressor::get(-1);
	}

	/**
	 * Returns the default compression method
	 */
	static protocol_compression_method get_default()
	{
		return s_default_compression;
	}

	/**
	 * Sets the stored default compression method
	 */
	static void set_default(protocol_compression_method new_method)
	{
		s_default_compression = new_method;
	}

private:
	static protocol_compression_method s_default_compression;
};
