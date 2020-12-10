
#include "handshake.pb.h"

/**
 * Helpers to convert from protobuf definitions to agent 
 * definitions. This interface is provided to reduce the number 
 * of dependencies needed by the agent's business logic.
 */
namespace handshake_helpers
{

/**
 * Convert from custom_metric_limit_value enumeration to uint32
 */
uint32_t metric_limit_to_uint32(draiosproto::custom_metric_limit_value value);

}
