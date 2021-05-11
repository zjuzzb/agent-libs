#pragma once

#include "common_logger.h"
#include "protocol.h"
#include "zlib.h"

#include <memory>

class protobuf_compressor
{
public:
	protobuf_compressor(protocol_compression_method compression_method)
	    : m_compression_method(compression_method)
	{
	}
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
class null_protobuf_compressor : public protobuf_compressor
{
public:
	null_protobuf_compressor() : protobuf_compressor(protocol_compression_method::NONE) {}

	bool compress(const google::protobuf::MessageLite& message,
	              google::protobuf::io::StringOutputStream& string_output) override;

	static std::shared_ptr<protobuf_compressor> get()
	{
		return std::shared_ptr<protobuf_compressor>(new null_protobuf_compressor);
	}
};

/**
 * Gzips the given protobuf and writes it to the given output stream.
 */
class gzip_protobuf_compressor : public protobuf_compressor
{
public:
	gzip_protobuf_compressor(int compression_level);

	bool compress(const google::protobuf::MessageLite& message,
	              google::protobuf::io::StringOutputStream& string_output) override;

	int get_compression_level() const { return m_compression_level; }

	static std::shared_ptr<protobuf_compressor> get(int compression_level)
	{
		return std::shared_ptr<protobuf_compressor>(
		    new gzip_protobuf_compressor(compression_level));
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
	static std::shared_ptr<protobuf_compressor> get(protocol_compression_method compression);

	/**
	 * Returns the default compressor
	 */
	static std::shared_ptr<protobuf_compressor> get_default_compressor();

	/**
	 * returns the default compression method
	 */
	static protocol_compression_method  get_default();
};
