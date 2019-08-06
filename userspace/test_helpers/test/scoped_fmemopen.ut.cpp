/**
 * @file
 *
 * Unit tests for scoped_fmemopen.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "scoped_fmemopen.h"
#include <gtest.h>

using test_helpers::scoped_fmemopen;

/**
 * Ensure that the FILE* is non-null after construction.
 */
TEST(scoped_fmemopen_test, initial_state_file_nonnull)
{
	const size_t capacity = 8;
	scoped_fmemopen buffer(capacity, "w");

	ASSERT_NE(nullptr, buffer.get_file());
}

/**
 * Ensure that the default content is the empty string.
 */
TEST(scoped_fmemopen_test, initial_state_default_content_empty)
{
	const size_t capacity = 8;
	scoped_fmemopen buffer(capacity, "w");

	ASSERT_EQ("", buffer.get_buffer_content());
}

/**
 * Ensure that if initial content is provided at construction time,
 * get_buffer_content() returns that content.
 */
TEST(scoped_fmemopen_test, initial_state_content_provided)
{
	std::string content = "this is some content";
	scoped_fmemopen buffer(content.size(), "w", content);

	ASSERT_EQ(content, buffer.get_buffer_content());
}

/**
 * Ensure that set_buffer_content() updates the content when the new content fits.
 */
TEST(scoped_fmemopen_test, set_buffer_content_new_content_fits)
{
	const size_t capacity = 8;
	scoped_fmemopen buffer(capacity, "w");
	const std::string new_content = "new";

	buffer.set_buffer_content(new_content);

	ASSERT_EQ(new_content, buffer.get_buffer_content());
}

/**
 * Ensure that set_buffer_content() updates the content when the new content
 * does not fit by truncating the new content.
 */
TEST(scoped_fmemopen_test, set_buffer_content_new_content_does_not_fit)
{
	const size_t capacity = 8;
	scoped_fmemopen buffer(capacity, "w");
	const std::string new_content = "new content does not fit";
	const std::string new_content_fits = new_content.substr(0, capacity);

	buffer.set_buffer_content(new_content);

	ASSERT_EQ(new_content_fits, buffer.get_buffer_content());
}

/**
 * Ensure we can use stdio routines to write to the FILE* associated with
 * a scoped_fmemopen.
 */
TEST(scoped_fmemopen_test, write_to_file_once)
{
	const size_t capacity = 32;
	scoped_fmemopen buffer(capacity, "w");
	const std::string content = "Hello, world!";

	fprintf(buffer.get_file(), "%s", content.c_str());

	ASSERT_EQ(content, buffer.get_buffer_content());
}

/**
 * Ensure we can use stdio routines to write multiple times to the FILE*
 * associated with a scoped_fmemopen.
 */
TEST(scoped_fmemopen_test, write_to_file_twice)
{
	const size_t capacity = 32;
	scoped_fmemopen buffer(capacity, "w");
	const std::string hello = "Hello, ";
	const std::string world = "world!";
	const std::string content = hello + world;

	fprintf(buffer.get_file(), "%s", hello.c_str());
	fprintf(buffer.get_file(), "%s", world.c_str());

	ASSERT_EQ(content, buffer.get_buffer_content());
}

/**
 * Ensure that if a stdio FILE* API tries to write too much, that only what
 * fits will be copied to the buffer.
 */
TEST(scoped_fmemopen_test, write_too_much)
{
	const std::string hello = "Hello";
	const std::string world = ", world!";
	const std::string content = hello + world;
	scoped_fmemopen buffer(hello.size(), "w");

	fprintf(buffer.get_file(), "%s", content.c_str());

	ASSERT_EQ(hello, buffer.get_buffer_content());
}

/**
 * Ensure we can use stdio routines to read from the FILE* associated with
 * a scoped_fmemopen.
 */
TEST(scoped_fmemopen_test, read_from_file_once)
{
	const size_t capacity = 32;
	const std::string content = "Hello, world!";
	scoped_fmemopen buffer(capacity, "r", content);

	char array[capacity] = {};
	fgets(array, sizeof(array), buffer.get_file());

	ASSERT_EQ(content, std::string(array));
}

/**
 * Ensure we can use stdio routines to read multiple times from the FILE*
 * associated with a scoped_fmemopen.
 */
TEST(scoped_fmemopen_test, read_from_file_twice)
{
	const size_t capacity = 32;
	const std::string hello = "Hello,";
	const std::string world = "world!";
	const std::string content = hello + " " + world;
	scoped_fmemopen buffer(capacity, "r", content);

	char array[capacity] = {};
	fscanf(buffer.get_file(), "%s", array);
	ASSERT_EQ(hello, std::string(array));

	fscanf(buffer.get_file(), "%s", array);
	ASSERT_EQ(world, std::string(array));
}
