#pragma once

#include <memory>

#include "prom_base.h"
#include "promscrape_conf.h"
#include "limits/metric_limits.h"

class prom_factory_helper
{

public:

static std::shared_ptr<prom_base> get(metric_limits::sptr_t ml, const promscrape_conf &prom_conf, bool threaded, prom_base::interval_cb_t interval_cb);
};
