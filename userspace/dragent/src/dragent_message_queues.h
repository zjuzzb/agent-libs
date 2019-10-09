/**
 * @file
 *
 * Definitions for the message queues used to pass metric data down the
 * pipeline from the data sources (such as the analyzer) to the data
 * transmitter (connection_manager).
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */

#pragma once

#include <memory>

#include "protocol.h"
#include "blocking_queue.h"
#include "analyzer_flush_message.h"

typedef std::shared_ptr<flush_data_message> flush_data;

typedef blocking_queue<flush_data> flush_queue;
typedef blocking_queue<std::shared_ptr<serialized_buffer>> protocol_queue;
