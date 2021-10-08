package server

import (
	"log"

	"github.com/prometheus/client_golang/prometheus"

	"os"
	draiosproto "protorepo/agent-be/proto"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	pb "github.com/draios/protorepo/promex_pb"
	"golang.org/x/net/context"
)

type prometheusMetricValue struct {
	value  float64
	labels []string
}

type prometheusMetric struct {
	description *prometheus.Desc
	valueType   prometheus.ValueType
	function    func(*prometheusExporterServer) ([]prometheusMetricValue, error)
}

type prometheusExporterServer struct {
	containerLabels []string
	metricTimeout   int
	metricsLock     sync.Mutex
	lastMetrics     *draiosproto.Metrics
	lastMetricsTime time.Time
	promAliveMetric prometheusMetric
	promMetrics     []prometheusMetric
}

func (s *prometheusExporterServer) EmitMetrics(_ context.Context, msg *draiosproto.Metrics) (*pb.PrometheusExporterResponse, error) {
	s.metricsLock.Lock()
	defer s.metricsLock.Unlock()

	s.lastMetricsTime = time.Now()
	s.lastMetrics = msg
	return &pb.PrometheusExporterResponse{}, nil
}

func (s *prometheusExporterServer) CheckLock() {
	s.metricsLock.Lock()
	s.metricsLock.Unlock()
}

// XXX: always copies by value
func derefOrEmpty(sp *string) string {
	if sp == nil {
		return ""
	} else {
		return *sp
	}
}

func singleOrAggrValueU32(single *uint32, aggr *draiosproto.Aggregations64) float64 {
	if aggr != nil {
		return float64(*aggr.Sum) / float64(*aggr.Weight)
	}
	if single != nil {
		return float64(*single)
	}
	return 0.0
}

func singleOrAggrValueU64(single *uint64, aggr *draiosproto.Aggregations64) float64 {
	if aggr != nil {
		return float64(*aggr.Sum) / float64(*aggr.Weight)
	}
	if single != nil {
		return float64(*single)
	}
	return 0.0
}

func singleOrAggrPercentages(single []uint32, aggr *draiosproto.Aggregations64Repeated) []prometheusMetricValue {
	var percentages []prometheusMetricValue

	if aggr != nil {
		for i, cpu := range aggr.Sum {
			percentages = append(percentages, prometheusMetricValue{
				float64(cpu) / (float64(*aggr.Weight) * 100.0),
				[]string{
					strconv.Itoa(i),
				},
			})
		}
	} else if single != nil {
		for i, cpu := range single {
			percentages = append(percentages, prometheusMetricValue{
				float64(cpu) / 100.0,
				[]string{
					strconv.Itoa(i),
				},
			})
		}
	}
	return percentages
}

func (s *prometheusExporterServer) containerLabelValues(container *draiosproto.Container) []string {
	labels := []string{
		derefOrEmpty(container.Id),
		derefOrEmpty(container.Name),
		container.Type.String(),
		derefOrEmpty(container.Image),
		derefOrEmpty(container.ImageDigest),
	}

	for _, label := range s.containerLabels {
		value := ""
		for _, pbLabel := range container.Labels {
			if *pbLabel.Key == label {
				value = *pbLabel.Value
				break
			}
		}
		labels = append(labels, value)
	}

	return labels
}

func (s *prometheusExporterServer) MustRegisterMetrics() {
	promContainerLabels := append([]string{
		"container_id",
		"container_name",
		"container_type",
		"container_image",
		"container_image_digest",
	}, buildContainerLabels(s.containerLabels)...)

	// global "are we up" metric
	s.promAliveMetric = prometheusMetric{
		description: prometheus.NewDesc(
			"sysdig_up",
			"Basic Prometheus exporter status",
			nil,
			nil,
		),
		valueType: prometheus.GaugeValue,
		function: func(server *prometheusExporterServer) ([]prometheusMetricValue, error) {
			up := 0.0
			if server.lastMetrics != nil {
				age := time.Since(server.lastMetricsTime)
				if age.Seconds() < float64(server.metricTimeout) {
					up = 1.0
				}
			}

			return []prometheusMetricValue{{up, nil}}, nil
		},
	}

	s.promMetrics = []prometheusMetric{
		{
			description: prometheus.NewDesc(
				"sysdig_sampling_ratio",
				"Sampling ratio of the Sysdig agent",
				nil,
				nil,
			),
			valueType: prometheus.GaugeValue,
			function: func(server *prometheusExporterServer) ([]prometheusMetricValue, error) {
				return []prometheusMetricValue{{
					singleOrAggrValueU32(s.lastMetrics.SamplingRatio, s.lastMetrics.AggrSamplingRatio),
					nil,
				}}, nil
			},
		},

		// host-wide CPU cpu metrics
		{
			description: prometheus.NewDesc(
				"host_cpu_used_percent",
				"Per-CPU load, in percent",
				[]string{"cpu"},
				nil,
			),
			valueType: prometheus.GaugeValue,
			function: func(server *prometheusExporterServer) ([]prometheusMetricValue, error) {
				cpus := singleOrAggrPercentages(
					s.lastMetrics.Hostinfo.CpuLoads,
					s.lastMetrics.Hostinfo.AggrCpuLoads,
				)
				return cpus, nil
			},
		},
		{
			description: prometheus.NewDesc(
				"host_cpu_idle_percent",
				"Per-CPU idle time, in percent",
				[]string{"cpu"},
				nil,
			),
			valueType: prometheus.GaugeValue,
			function: func(server *prometheusExporterServer) ([]prometheusMetricValue, error) {
				cpus := singleOrAggrPercentages(
					s.lastMetrics.Hostinfo.CpuIdle,
					s.lastMetrics.Hostinfo.AggrCpuIdle,
				)
				return cpus, nil
			},
		},
		{
			description: prometheus.NewDesc(
				"host_cpu_iowait_percent",
				"Per-CPU I/O wait time, in percent",
				[]string{"cpu"},
				nil,
			),
			valueType: prometheus.GaugeValue,
			function: func(server *prometheusExporterServer) ([]prometheusMetricValue, error) {
				cpus := singleOrAggrPercentages(
					s.lastMetrics.Hostinfo.IowaitCpu,
					s.lastMetrics.Hostinfo.AggrIowaitCpu,
				)
				return cpus, nil
			},
		},
		{
			description: prometheus.NewDesc(
				"host_cpu_nice_percent",
				"Per-CPU nice time, in percent",
				[]string{"cpu"},
				nil,
			),
			valueType: prometheus.GaugeValue,
			function: func(server *prometheusExporterServer) ([]prometheusMetricValue, error) {
				cpus := singleOrAggrPercentages(
					s.lastMetrics.Hostinfo.NiceCpu,
					s.lastMetrics.Hostinfo.AggrNiceCpu,
				)
				return cpus, nil
			},
		},
		{
			description: prometheus.NewDesc(
				"host_cpu_stolen_percent",
				"Per-CPU stolen time, in percent",
				[]string{"cpu"},
				nil,
			),
			valueType: prometheus.GaugeValue,
			function: func(server *prometheusExporterServer) ([]prometheusMetricValue, error) {
				cpus := singleOrAggrPercentages(
					s.lastMetrics.Hostinfo.CpuSteal,
					s.lastMetrics.Hostinfo.AggrCpuSteal,
				)
				return cpus, nil
			},
		},
		{
			description: prometheus.NewDesc(
				"host_cpu_system_percent",
				"Per-CPU system time, in percent",
				[]string{"cpu"},
				nil,
			),
			valueType: prometheus.GaugeValue,
			function: func(server *prometheusExporterServer) ([]prometheusMetricValue, error) {
				cpus := singleOrAggrPercentages(
					s.lastMetrics.Hostinfo.SystemCpu,
					s.lastMetrics.Hostinfo.AggrSystemCpu,
				)
				return cpus, nil
			},
		},
		{
			description: prometheus.NewDesc(
				"host_cpu_user_percent",
				"Per-CPU user time, in percent",
				[]string{"cpu"},
				nil,
			),
			valueType: prometheus.GaugeValue,
			function: func(server *prometheusExporterServer) ([]prometheusMetricValue, error) {
				cpus := singleOrAggrPercentages(
					s.lastMetrics.Hostinfo.UserCpu,
					s.lastMetrics.Hostinfo.AggrUserCpu,
				)
				return cpus, nil
			},
		},
		// host-wide memory metrics
		{
			description: prometheus.NewDesc(
				"host_memory_bytes_total",
				"Total physical memory, in bytes",
				nil,
				nil,
			),
			valueType: prometheus.GaugeValue,
			function: func(server *prometheusExporterServer) ([]prometheusMetricValue, error) {
				return []prometheusMetricValue{
					{singleOrAggrValueU64(
						s.lastMetrics.Hostinfo.PhysicalMemorySizeBytes,
						s.lastMetrics.Hostinfo.AggrPhysicalMemorySizeBytes,
					), nil},
				}, nil
			},
		},
		{
			description: prometheus.NewDesc(
				"host_memory_bytes_available",
				"Available memory, in bytes",
				nil,
				nil,
			),
			valueType: prometheus.GaugeValue,
			function: func(server *prometheusExporterServer) ([]prometheusMetricValue, error) {
				return []prometheusMetricValue{
					{singleOrAggrValueU64(
						s.lastMetrics.Hostinfo.MemoryBytesAvailableKb,
						s.lastMetrics.Hostinfo.AggrMemoryBytesAvailableKb,
					) * 1024, nil},
				}, nil
			},
		},
		{
			description: prometheus.NewDesc(
				"host_memory_bytes_used",
				"Used memory, in bytes",
				nil,
				nil,
			),
			valueType: prometheus.GaugeValue,
			function: func(server *prometheusExporterServer) ([]prometheusMetricValue, error) {
				return []prometheusMetricValue{
					{singleOrAggrValueU32(
						s.lastMetrics.Hostinfo.ResourceCounters.ResidentMemoryUsageKb,
						s.lastMetrics.Hostinfo.ResourceCounters.AggrResidentMemoryUsageKb,
					) * 1024, nil},
				}, nil
			},
		},
		{
			description: prometheus.NewDesc(
				"host_memory_bytes_virtual",
				"Allocated virtual memory, in bytes",
				nil,
				nil,
			),
			valueType: prometheus.GaugeValue,
			function: func(server *prometheusExporterServer) ([]prometheusMetricValue, error) {
				var virtual uint64
				for _, prog := range s.lastMetrics.Programs {
					progVirtual := singleOrAggrValueU32(
						prog.Procinfo.ResourceCounters.VirtualMemoryUsageKb,
						prog.Procinfo.ResourceCounters.AggrVirtualMemoryUsageKb,
					)
					virtual = virtual + (uint64(progVirtual) * 1024)
				}
				return []prometheusMetricValue{
					{float64(virtual), nil},
				}, nil
			},
		},

		// host-wide swap metrics
		{
			description: prometheus.NewDesc(
				"host_memory_swap_bytes_total",
				"Total swap space, in bytes",
				nil,
				nil,
			),
			valueType: prometheus.GaugeValue,
			function: func(server *prometheusExporterServer) ([]prometheusMetricValue, error) {
				return []prometheusMetricValue{
					{singleOrAggrValueU32(
						s.lastMetrics.Hostinfo.ResourceCounters.SwapMemoryTotalKb,
						s.lastMetrics.Hostinfo.ResourceCounters.AggrSwapMemoryTotalKb,
					) * 1024.0, nil},
				}, nil
			},
		},
		{
			description: prometheus.NewDesc(
				"host_memory_swap_bytes_available",
				"Available swap space, in bytes",
				nil,
				nil,
			),
			valueType: prometheus.GaugeValue,
			function: func(server *prometheusExporterServer) ([]prometheusMetricValue, error) {
				return []prometheusMetricValue{
					{singleOrAggrValueU32(
						s.lastMetrics.Hostinfo.ResourceCounters.SwapMemoryAvailableKb,
						s.lastMetrics.Hostinfo.ResourceCounters.AggrSwapMemoryAvailableKb,
					) * 1024.0, nil},
				}, nil
			},
		},
		{
			description: prometheus.NewDesc(
				"host_memory_swap_bytes_used",
				"Used swap space, in bytes",
				nil,
				nil,
			),
			valueType: prometheus.GaugeValue,
			function: func(server *prometheusExporterServer) ([]prometheusMetricValue, error) {
				return []prometheusMetricValue{
					{singleOrAggrValueU32(
						s.lastMetrics.Hostinfo.ResourceCounters.SwapMemoryUsageKb,
						s.lastMetrics.Hostinfo.ResourceCounters.AggrSwapMemoryUsageKb,
					) * 1024.0, nil},
				}, nil
			},
		},

		// per-container CPU metrics
		{
			description: prometheus.NewDesc(
				"container_cpu_used_percent",
				"CPU used percentage, per container",
				promContainerLabels,
				nil,
			),
			valueType: prometheus.GaugeValue,
			function: func(server *prometheusExporterServer) ([]prometheusMetricValue, error) {
				var metrics []prometheusMetricValue
				for _, container := range s.lastMetrics.Containers {
					containerCpu := singleOrAggrValueU32(
						container.ResourceCounters.CpuPct,
						container.ResourceCounters.AggrCpuPct,
					)
					metrics = append(metrics, prometheusMetricValue{
						value:  containerCpu / 100.0,
						labels: s.containerLabelValues(container),
					})
				}

				return metrics, nil
			},
		},

		// per-container memory metrics
		{
			description: prometheus.NewDesc(
				"container_memory_bytes_used",
				"RSS memory used, per container",
				promContainerLabels,
				nil,
			),
			valueType: prometheus.GaugeValue,
			function: func(server *prometheusExporterServer) ([]prometheusMetricValue, error) {
				var metrics []prometheusMetricValue
				for _, container := range s.lastMetrics.Containers {
					containerMem := singleOrAggrValueU32(
						container.ResourceCounters.ResidentMemoryUsageKb,
						container.ResourceCounters.AggrResidentMemoryUsageKb,
					)
					metrics = append(metrics, prometheusMetricValue{
						value:  containerMem * 1024.0,
						labels: s.containerLabelValues(container),
					})
				}

				return metrics, nil
			},
		},

		// File I/O metrics, per host
		{
			description: prometheus.NewDesc(
				"host_file_time_in",
				"File read time, in seconds",
				nil,
				nil,
			),
			valueType: prometheus.GaugeValue,
			function: func(server *prometheusExporterServer) ([]prometheusMetricValue, error) {
				return []prometheusMetricValue{
					{
						value: singleOrAggrValueU64(
							s.lastMetrics.Hostinfo.Tcounters.IoFile.TimeNsIn,
							s.lastMetrics.Hostinfo.Tcounters.IoFile.AggrTimeNsIn,
						) / 1e9,
						labels: nil,
					},
				}, nil
			},
		},
		{
			description: prometheus.NewDesc(
				"host_file_time_out",
				"File write time, in seconds",
				nil,
				nil,
			),
			valueType: prometheus.GaugeValue,
			function: func(server *prometheusExporterServer) ([]prometheusMetricValue, error) {
				return []prometheusMetricValue{
					{
						value: singleOrAggrValueU64(
							s.lastMetrics.Hostinfo.Tcounters.IoFile.TimeNsOut,
							s.lastMetrics.Hostinfo.Tcounters.IoFile.AggrTimeNsOut,
						) / 1e9,
						labels: nil,
					},
				}, nil
			},
		},
		{
			description: prometheus.NewDesc(
				"host_file_time_other",
				"Other file I/O time, in seconds",
				nil,
				nil,
			),
			valueType: prometheus.GaugeValue,
			function: func(server *prometheusExporterServer) ([]prometheusMetricValue, error) {
				return []prometheusMetricValue{
					{
						value: singleOrAggrValueU64(
							s.lastMetrics.Hostinfo.Tcounters.IoFile.TimeNsOther,
							s.lastMetrics.Hostinfo.Tcounters.IoFile.AggrTimeNsOther,
						) / 1e9,
						labels: nil,
					},
				}, nil
			},
		},

		// File I/O metrics, per container
		{
			description: prometheus.NewDesc(
				"container_file_time_in",
				"File read time per container, in seconds",
				promContainerLabels,
				nil,
			),
			valueType: prometheus.GaugeValue,
			function: func(server *prometheusExporterServer) ([]prometheusMetricValue, error) {
				var metrics []prometheusMetricValue
				for _, container := range s.lastMetrics.Containers {
					metrics = append(metrics, prometheusMetricValue{
						value: singleOrAggrValueU64(
							container.Tcounters.IoFile.TimeNsIn,
							container.Tcounters.IoFile.AggrTimeNsIn,
						) / 1e9,
						labels: s.containerLabelValues(container),
					})
				}

				return metrics, nil
			},
		},
		{
			description: prometheus.NewDesc(
				"container_file_time_out",
				"File write time per container, in seconds",
				promContainerLabels,
				nil,
			),
			valueType: prometheus.GaugeValue,
			function: func(server *prometheusExporterServer) ([]prometheusMetricValue, error) {
				var metrics []prometheusMetricValue
				for _, container := range s.lastMetrics.Containers {
					metrics = append(metrics, prometheusMetricValue{
						value: singleOrAggrValueU64(
							container.Tcounters.IoFile.TimeNsOut,
							container.Tcounters.IoFile.AggrTimeNsOut,
						) / 1e9,
						labels: s.containerLabelValues(container),
					})
				}

				return metrics, nil
			},
		},
		{
			description: prometheus.NewDesc(
				"container_file_time_other",
				"Other file I/O time per container, in seconds",
				promContainerLabels,
				nil,
			),
			valueType: prometheus.GaugeValue,
			function: func(server *prometheusExporterServer) ([]prometheusMetricValue, error) {
				var metrics []prometheusMetricValue
				for _, container := range s.lastMetrics.Containers {
					metrics = append(metrics, prometheusMetricValue{
						value: singleOrAggrValueU64(
							container.Tcounters.IoFile.TimeNsOther,
							container.Tcounters.IoFile.AggrTimeNsOther,
						) / 1e9,
						labels: s.containerLabelValues(container),
					})
				}

				return metrics, nil
			},
		},

		// swap metrics, per container
		{
			description: prometheus.NewDesc(
				"container_memory_swap_bytes_used",
				"Used swap space per container, in bytes",
				promContainerLabels,
				nil,
			),
			valueType: prometheus.GaugeValue,
			function: func(server *prometheusExporterServer) ([]prometheusMetricValue, error) {
				var metrics []prometheusMetricValue
				for _, container := range s.lastMetrics.Containers {
					metrics = append(metrics, prometheusMetricValue{
						value: singleOrAggrValueU32(
							container.ResourceCounters.SwapMemoryUsageKb,
							container.ResourceCounters.AggrSwapMemoryUsageKb,
						) * 1024.0,
						labels: s.containerLabelValues(container),
					})
				}

				return metrics, nil
			},
		},
	}

	prometheus.MustRegister(s)
}

func (s *prometheusExporterServer) Describe(ch chan<- *prometheus.Desc) {
	for _, metric := range s.promMetrics {
		ch <- metric.description
	}
}

func (s *prometheusExporterServer) Collect(ch chan<- prometheus.Metric) {
	s.metricsLock.Lock()
	defer s.metricsLock.Unlock()

	up, _ := s.promAliveMetric.function(s)
	ch <- prometheus.MustNewConstMetric(
		s.promAliveMetric.description,
		s.promAliveMetric.valueType,
		up[0].value,
		up[0].labels...,
	)

	if s.lastMetrics == nil {
		log.Printf("Info: No metrics collected yet")
		return
	}

	for _, metric := range s.promMetrics {
		values, err := metric.function(s)
		if err != nil {
			log.Printf("Warning: Failed to calculate metric %v: %v", metric.description, err)
			continue
		}

		for _, value := range values {
			ch <- prometheus.MustNewConstMetric(metric.description, metric.valueType, value.value, value.labels...)
		}
	}
}

func filterContainerLabels(containerLabels []string) []string {
	var promLabels []string
	for _, l := range containerLabels {
		l := strings.TrimSpace(l)
		if l != "" {
			match, _ := regexp.MatchString("^[a-zA-Z0-9:_]+$", l)
			if match {
				promLabels = append(promLabels, l)
			} else {
				log.Printf("Warning: %s is not a valid Prometheus label, skipping", l)
			}
		}
	}

	return promLabels
}

func buildContainerLabels(containerLabels []string) []string {
	var promLabels []string
	for _, l := range containerLabels {
		promLabels = append(promLabels, "label_"+l)
	}

	return promLabels
}

func NewServer(containerLabels []string, timeout int) *prometheusExporterServer {
	s := &prometheusExporterServer{
		containerLabels: filterContainerLabels(containerLabels),
		metricTimeout:   timeout,
	}
	prometheus.Unregister(prometheus.NewProcessCollector(os.Getpid(), ""))
	prometheus.Unregister(prometheus.NewGoCollector())
	s.MustRegisterMetrics()
	return s
}
