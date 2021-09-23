#pragma once

#include <memory>

#include "prom_base.h"
#include "prometheus.h"
#include "limits/metric_limits.h"

class prom_factory
{

public:

static std::shared_ptr<prom_base> get(metric_limits::sptr_t ml, const prometheus_conf &prom_conf, bool threaded, prom_base::interval_cb_t interval_cb);
};
