from checks import AgentCheck

class MyCustomCheck(AgentCheck):
    def __init__(self, name, init_config, agentConfig):
        AgentCheck.__init__(self, name, init_config, agentConfig)
        self.counter = 0

    def check(self, instance):
        for x in range(300):
            self.gauge("metric_%d" % self.counter, 5)
            self.counter += 1
