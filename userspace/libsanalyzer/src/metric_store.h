/**
 * @file
 *
 * Interface to namespace metric_store.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once
#include <memory>

namespace draiosproto {
class metrics;
}

namespace libsanalyzer {

/**
 * A place in which to store a reference to the latest complete metrics
 * protobuf.
 */
namespace metric_store {

/**
 * Saves a complete metrics protobuf.
 */
void store(const std::shared_ptr<const draiosproto::metrics>& metrics);

/**
 * Returns the last complete protobuf, or nullptr if there has never been
 * a complete protobuf.
 */
std::shared_ptr<const draiosproto::metrics> get();

} // namespace metric_store
} // namespace libsanalyzer
