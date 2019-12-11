#pragma once
#include "draios.pb.h"
#include "Poco/Net/HTTPServer.h"
#include <memory>
#include <string>

namespace rest_metrics
{
std::string metrics_fetcher_helper(Poco::Net::HTTPServerResponse& response,
                                   const std::shared_ptr<const draiosproto::metrics> metrics);
}
