#define STATSD_METRIC(name, type, value)				\
		new_metric = expected.mutable_statsd_metrics()->Add();	\
		new_metric->set_name(#name);				\
		new_metric->set_type(draiosproto::type);		\
		new_metric->set_value(value);

// Hey order matters! It must be the same as internal_metric class adds metrics
// in send_some and send_all class
SOME({
STATSD_METRIC(dragent.metricCount.limit.appCheck	, STATSD_GAUGE, 500)
STATSD_METRIC(dragent.metricCount.limit.statsd		, STATSD_GAUGE, 100)
STATSD_METRIC(dragent.metricCount.limit.jmx		, STATSD_GAUGE, 500)
STATSD_METRIC(dragent.metricCount.limit.prometheus	, STATSD_GAUGE, 3000)
STATSD_METRIC(dragent.log.err				, STATSD_COUNT, 1)
STATSD_METRIC(dragent.log.warn				, STATSD_COUNT, 1)
STATSD_METRIC(dragent.log.info				, STATSD_COUNT, 1)
STATSD_METRIC(dragent.log.debug				, STATSD_COUNT, 1)
STATSD_METRIC(dragent.analyzer.max_sinsp_buf_used	, STATSD_GAUGE, 0)
STATSD_METRIC(dragent.analyzer.mesos.autodetect		, STATSD_GAUGE, 0)
STATSD_METRIC(dragent.analyzer.mesos.detected		, STATSD_GAUGE, 0)
})


ALL({
STATSD_METRIC(dragent.metricCount.limit.appCheck		, STATSD_GAUGE, 500)
STATSD_METRIC(dragent.metricCount.limit.statsd			, STATSD_GAUGE, 100)
STATSD_METRIC(dragent.metricCount.limit.jmx			, STATSD_GAUGE, 500)
STATSD_METRIC(dragent.metricCount.limit.prometheus		, STATSD_GAUGE, 3000)
STATSD_METRIC(dragent.log.err					, STATSD_COUNT, 0)
STATSD_METRIC(dragent.log.warn					, STATSD_COUNT, 0)
STATSD_METRIC(dragent.log.info					, STATSD_COUNT, 0)
STATSD_METRIC(dragent.log.debug					, STATSD_COUNT, 0)
STATSD_METRIC(dragent.analyzer.max_sinsp_buf_used		, STATSD_GAUGE, 995)
STATSD_METRIC(dragent.analyzer.processes			, STATSD_GAUGE, 999)
STATSD_METRIC(dragent.analyzer.threads				, STATSD_GAUGE, 999)
STATSD_METRIC(dragent.analyzer.containers			, STATSD_GAUGE, 999)
STATSD_METRIC(dragent.analyzer.javaprocs			, STATSD_GAUGE, 999)
STATSD_METRIC(dragent.analyzer.appchecks			, STATSD_GAUGE, 999)
STATSD_METRIC(dragent.analyzer.mesos.autodetect			, STATSD_GAUGE, 1)
STATSD_METRIC(dragent.analyzer.mesos.detected			, STATSD_GAUGE, 1)
STATSD_METRIC(dragent.analyzer.fp.pct100			, STATSD_GAUGE, 999)
STATSD_METRIC(dragent.analyzer.fl.ms				, STATSD_GAUGE, 999)
STATSD_METRIC(dragent.analyzer.sr				, STATSD_GAUGE, 999)
STATSD_METRIC(dragent.analyzer.cpu_percentage			, STATSD_GAUGE, 999)
STATSD_METRIC(dragent.analyzer.n_evts				, STATSD_GAUGE, 999)
STATSD_METRIC(dragent.analyzer.n_drops				, STATSD_GAUGE, 998)
STATSD_METRIC(dragent.analyzer.n_drops_buffer			, STATSD_GAUGE, 997)
STATSD_METRIC(dragent.analyzer.n_preemptions			, STATSD_GAUGE, 996)
STATSD_METRIC(dragent.subproc.agent.cpu.pct100			, STATSD_GAUGE, 999)
STATSD_METRIC(dragent.subproc.agent.memory.kb			, STATSD_GAUGE, 999)
STATSD_METRIC(dragent.subproc.java.cpu.pct100			, STATSD_GAUGE, 999)
STATSD_METRIC(dragent.subproc.java.memory.kb			, STATSD_GAUGE, 999)
STATSD_METRIC(dragent.subproc.appcheck.cpu.pct100		, STATSD_GAUGE, 999)
STATSD_METRIC(dragent.subproc.appcheck.memory.kb		, STATSD_GAUGE, 999)
STATSD_METRIC(dragent.subproc.mountedfs.reader.cpu.pct100	, STATSD_GAUGE, 999)
STATSD_METRIC(dragent.subproc.mountedfs.reader.memory.kb	, STATSD_GAUGE, 999)
STATSD_METRIC(dragent.subproc.cointerface.cpu.pct100		, STATSD_GAUGE, 999)
STATSD_METRIC(dragent.subproc.cointerface.memory.kb		, STATSD_GAUGE, 999)
STATSD_METRIC(dragent.subproc.statsite.forwarder.cpu.pct100	, STATSD_GAUGE, 999)
STATSD_METRIC(dragent.subproc.statsite.forwarder.memory.kb	, STATSD_GAUGE, 999)
})



#undef STATDS_METRIC
#undef SOME
#undef ALL
