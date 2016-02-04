# project
from checks import AgentCheck
from utils.voltdbclient import FastSerializer
from utils.voltdbclient import VoltProcedure

class VoltDB(AgentCheck):
    NEEDED_NS = ( 'net', )

    def __init__(self, name, init_config, agentConfig):
        AgentCheck.__init__(self, name, init_config, agentConfig)
        self.client = None

    def check(self, instance):
        if not self.client:
            self.client = FastSerializer(instance.get("host", "localhost"), instance.get('port', 21212))
        
        proc = VoltProcedure(self.client, "@Statistics", [FastSerializer.VOLTTYPE_STRING, FastSerializer.VOLTTYPE_TINYINT])
        response = proc.call(["TABLE", 0])

        for data in response.tables[0].tuples:
            # Data example:
            # [1454420905674, 0, u'46321180396e', 0, 0, u'AREA_CODE_STATE', u'PersistentTable', 305, 2048, 3, 0, None, 0]
            # [_, _, hostname, _, _, table_name, table_type, tuple_count, tuple_alloc_mem, tuple_data_mem, string_data_mem, tuple_limit, percent_full]
            tags = [
                "table.type:%s" % data[6],
                "table.name:%s" % data[5]
            ]
            self.gauge("voltdb.table.tuple_count", data[7], tags=tags)
            self.gauge("voltdb.table.tuple_alloc_mem", data[8] * 1024, tags=tags)
            self.gauge("voltdb.table.tuple_data_mem", data[9] * 1024, tags=tags)
            self.gauge("voltdb.table.string_data_mem", data[10] * 1024, tags=tags)
            self.gauge("voltdb.table.tuple_limit", data[11] or 0, tags=tags)
            self.gauge("voltdb.table.percent_full", data[12], tags=tags)
            
        response = proc.call(["PROCEDURE", 1])

        for data in response.tables[0].tuples:
            # [ _, _, hostname, _, _, proc_name, invocations, timed_invocations, min_time, max_time, avg_time, min_result_size, max_result_size, avg_result_size, min_param_set_size, max_param_set_size, avg_param_set_size, aborts, failures]
            tags = [
                "procedure.name:%s" % data[5],
            ]
            self.gauge("voltdb.procedures.invocations", data[6], tags=tags)
            self.gauge("voltdb.procedures.timed_invocations", data[7], tags=tags)
            self.gauge("voltdb.procedures.min_time", data[8] / 1000000.0, tags=tags)
            self.gauge("voltdb.procedures.max_time", data[9] / 1000000.0, tags=tags)
            self.gauge("voltdb.procedures.avg_time", data[10] / 1000000.0, tags=tags)
            self.gauge("voltdb.procedures.min_result_size", data[11], tags=tags)
            self.gauge("voltdb.procedures.max_result_size", data[12], tags=tags)
            self.gauge("voltdb.procedures.avg_result_size", data[13], tags=tags)
            self.gauge("voltdb.procedures.min_param_set_size", data[14], tags=tags)
            self.gauge("voltdb.procedures.max_param_set_size", data[15], tags=tags)
            self.gauge("voltdb.procedures.avg_param_set_size", data[16], tags=tags)
            self.gauge("voltdb.procedures.aborts", data[17], tags=tags)
            self.gauge("voltdb.procedures.failures", data[18], tags=tags)

        response = proc.call(["LIVECLIENTS", 0])

        for data in response.tables[0].tuples:
            # Data example:
            # [1454432474641, 0, u'46321180396e', 19, u'localhost', 0, 0, 0, 0]
            # [ _, _, hostname, connection_id, client_hostname, admin, outstanding_req_bytes, outstanding_res_msg, oustanding_tx]
            tags = [
                "client.admin:%s" % data[5],
                "client.host:%s" % data[4]
            ]
            self.gauge("voltdb.clients.outstanding_req_bytes", data[6], tags=tags)
            self.gauge("voltdb.clients.outstanding_res_msg", data[7], tags=tags)
            self.gauge("voltdb.clients.outstanding_tx", data[8], tags=tags)
            
        response = proc.call(["MEMORY", 0])

        for data in response.tables[0].tuples:
            # Data example:
            # [1454432474642, 0, u'46321180396e', 1787244, 203993, 877374, 328060, 393216, 462324, 0, 19194016, 82047, 4028416, 1014528]
            # [_, _, hostname, rss, java_used, java_unused, tuple_data, tuple_allocated, index_mem, string_mem, tuple_count, pooled_mem]
            self.gauge("voltdb.memory.rss", data[3] * 1024)
            self.gauge("voltdb.memory.java_used", data[4] * 1024)
            self.gauge("voltdb.memory.java_unused", data[5] * 1024)
            self.gauge("voltdb.memory.tuple_data", data[6] * 1024)
            self.gauge("voltdb.memory.tuple_allocated", data[7] * 1024)
            self.gauge("voltdb.memory.index_mem", data[8] * 1024)
            self.gauge("voltdb.memory.string_mem", data[9] * 1024)
            self.gauge("voltdb.memory.tuple_count", data[10])
            self.gauge("voltdb.memory.pooled_mem", data[11] * 1024)
