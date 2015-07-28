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
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final long VMS_CLEANUP_INTERVAL = 10 * 60 * 1000;

    static {
        MAPPER.disable(SerializationFeature.FLUSH_AFTER_WRITE_VALUE);
        MAPPER.configure(JsonGenerator.Feature.AUTO_CLOSE_TARGET, false);
        FilterProvider filters = new SimpleFilterProvider().addFilter("BeanAttributeDataFilter", new BeanData
                .BeanAttributeDataFilter());
        MAPPER.setFilters(filters);
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        try {
            Application app = new Application();
            LOGGER.info(String.format("Starting sdjagent with pid: %d", CLibrary.getPid()));
            LOGGER.info(String.format("Java version: %s", System.getProperty("java.version")));
            if(args.length > 0) {
                app.runWithArgs(args);
            } else {
                app.mainLoop();
            }
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

    private void runWithArgs(String[] args) throws IOException {
        if(args[0].equals("getVMHandle") && args.length > 1) {
            VMRequest request = new VMRequest(Integer.parseInt(args[1]), Integer.parseInt(args[1]));
            MonitoredVM vm = new MonitoredVM(request);
            Map<String, Object> vmInfo = new HashMap<String, Object>();
            vmInfo.put("available", vm.isAvailable());
            if(vm.isAvailable()) {
                vmInfo.put("name", vm.getName());
                vmInfo.put("agentActive", vm.isAgentActive());
                if (vm.isAgentActive()) {
                    vmInfo.put("address", vm.getAddress());
                }
            }
            MAPPER.writeValue(System.out, vmInfo);
        } else if (args[0].equals("getMetrics") && args.length > 2) {
            VMRequest request = new VMRequest(Integer.parseInt(args[1]), Integer.parseInt(args[2]));
            MonitoredVM vm = new MonitoredVM(request);
            vm.addQueries(config.getDefaultBeanQueries());
            MAPPER.writeValue(System.out, vm.getMetrics());
        }
        System.out.println();
        System.out.flush();
    }

    private void mainLoop() throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        while (true)
        {
            String cmd_data = reader.readLine();
            LOGGER.fine(String.format("Received command: %s", cmd_data));
            Map<String, Object> cmd_obj = MAPPER.readValue(cmd_data, Map.class);
            List<VMRequest> requestedVMs = new ArrayList<VMRequest>();
            if (cmd_obj.get("command").equals("getMetrics"))
            {
                List<Object> body = (List<Object>) cmd_obj.get("body");
                for(Object item : body) {
                    requestedVMs.add(MAPPER.convertValue(item, VMRequest.class));
                }
                List<Map<String, Object>> vmList = getMetricsCommand(requestedVMs);
                Map<String, Object> response_obj = new LinkedHashMap<String, Object>();
                response_obj.put("id", cmd_obj.get("id"));
                response_obj.put("body", vmList);
                MAPPER.writeValue(System.out, response_obj);
                System.out.println();
                System.out.flush();
                LOGGER.fine("End getMetrics command");
            }

            // Cleanup
            if(System.currentTimeMillis() - lastVmsCleanup > VMS_CLEANUP_INTERVAL) {
                cleanup(requestedVMs);
                lastVmsCleanup = System.currentTimeMillis();
            }
        }
    }

    private void cleanup(List<VMRequest> requestedVMs) {
        Set<Integer> activePids = new HashSet<Integer>();
        for (VMRequest requestedVM : requestedVMs) {
            activePids.add(requestedVM.getPid());
        }
        Iterator<Integer> vmsIt = vms.keySet().iterator();
        while (vmsIt.hasNext()) {
            Integer pid = vmsIt.next();
            if (!activePids.contains(pid)) {
                LOGGER.info(String.format("Removing cached entry for pid: %d", pid.intValue()));
                vmsIt.remove();
            }
        }
    }

    private List<Map<String, Object>> getMetricsCommand(List<VMRequest> requestedVMs) throws IOException {
        LOGGER.fine("Executing getMetrics");
        List<Map<String, Object>> vmList = new LinkedList<Map<String, Object>>();

        for (VMRequest request : requestedVMs) {
            Map<String, Object> vmObject = new LinkedHashMap<String, Object>();
            MonitoredVM vm = vms.get(request.getPid());

            if (vm == null) {
                vm = new MonitoredVM(request);
                vm.addQueries(config.getDefaultBeanQueries());
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
                vms.put(request.getPid(), vm);
            }

            if (vm.isAvailable()) {
                vmObject.put("pid", request.getPid());
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
