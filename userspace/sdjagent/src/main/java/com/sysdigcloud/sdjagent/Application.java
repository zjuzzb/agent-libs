/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sysdigcloud.sdjagent;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.ser.FilterProvider;
import com.fasterxml.jackson.databind.ser.impl.SimpleFilterProvider;


import java.io.*;
import java.util.*;
import java.util.logging.*;

/**
 *
 * @author Luca Marturana <luca@draios.com>
 */
public class Application {
    private static final Logger LOGGER = Logger.getLogger(Application.class.getName());
    private static final ObjectMapper mapper = new ObjectMapper();
    private static final long vmsCleanupInterval = 10 * 60 * 1000;

    static {
        mapper.disable(SerializationFeature.FLUSH_AFTER_WRITE_VALUE);
        mapper.configure(JsonGenerator.Feature.AUTO_CLOSE_TARGET, false);
        FilterProvider filters = new SimpleFilterProvider().addFilter("BeanAttributeDataFilter", new BeanData
                .BeanAttributeDataFilter());
        mapper.setFilters(filters);
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        try {
            Application app = new Application();
            LOGGER.info(String.format("Starting sdjagent with pid: %d", CLibrary.getPid()));
            app.mainLoop();
        } catch (IOException ex) {
            LOGGER.severe("IOException on main thread: " + ex.getMessage());
            System.exit(1);
        }
    }

    private HashMap<Integer, MonitoredVM> vms;
    private Config config;
    private long lastVmsCleanup;

    private Application() throws FileNotFoundException {
        LogManager.getLogManager().reset();
        Logger globalLogger = Logger.getLogger("");
        ConsoleHandler console = new ConsoleHandler();
        console.setFormatter(new LogJsonFormatter());
        globalLogger.addHandler(console);

        vms = new HashMap<Integer, MonitoredVM>();
        lastVmsCleanup = 0;
        config = new Config();

        Level level = config.getLogLevel();
        console.setLevel(level);
        globalLogger.setLevel(level);
    }

    private void mainLoop() throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        while (true)
        {
            String cmd_data = reader.readLine();
            LOGGER.fine(String.format("Received command: %s", cmd_data));
            Map<String, String> cmd_obj = mapper.readValue(cmd_data, Map.class);
            if (cmd_obj.get("command").equals("getMetrics"))
            {
                List<Map<String, Object>> vmList = getMetricsCommand();
                Map<String, Object> response_obj = new LinkedHashMap<String, Object>();
                response_obj.put("id", cmd_obj.get("id"));
                response_obj.put("body", vmList);
                mapper.writeValue(System.out, response_obj);
                System.out.println();
                System.out.flush();
                LOGGER.fine("End getMetrics command");
            }

            // Cleanup
            if(System.currentTimeMillis() - lastVmsCleanup > vmsCleanupInterval) {
                cleanup();
                lastVmsCleanup = System.currentTimeMillis();
            }
        }
    }

    private void cleanup() {
        Set<Integer> activePids = JvmstatVM.getActiveVMs();
        Iterator<Integer> vmsIt = vms.keySet().iterator();
        while (vmsIt.hasNext()) {
            Integer pid = vmsIt.next();
            if (!activePids.contains(pid)) {
                LOGGER.info(String.format("Removing cached entry for pid: %d", pid.intValue()));
                vmsIt.remove();
            }
        }
    }

    private List<Map<String, Object>> getMetricsCommand() throws IOException {
        LOGGER.fine("Executing getMetrics");
        List<Map<String, Object>> vmList = new LinkedList<Map<String, Object>>();

        for (Integer pid : JvmstatVM.getActiveVMs()) {
            LOGGER.fine(String.format("Found java process %s", pid.intValue()));
            Map<String, Object> vmObject = new LinkedHashMap<String, Object>();
            MonitoredVM vm = vms.get(pid);

            if (vm == null) {
                vm = new MonitoredVM(pid, config.getDefaultBeanQueries());

                // Configure VM name if it matches a pattern on configurations
                if(vm.isAvailable())
                {
                    Map<String, Config.Process> processes = config.getProcesses();
                    for (Map.Entry<String, Config.Process> config : processes.entrySet()) {
                        if (vm.getName().contains(config.getValue().getPattern())) {
                            vm.setName(config.getKey());
                            vm.addQueries(config.getValue().getQueries());
                            break;
                        }
                    }
                }

                // Add it to known VMs
                vms.put(pid, vm);
            }

            if (vm.isAvailable()) {
                vmObject.put("pid", pid);
                vmObject.put("name", vm.getName());

                if (vm.isAgentActive()) {
                    List<BeanData> beanDataList = vm.getMetrics();
                    vmObject.put("beans", beanDataList);
                }
                vmList.add(vmObject);
            }
        }
        return vmList;
    }
}
