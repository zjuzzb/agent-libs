/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sysdigcloud.sdjagent;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;


import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.*;
import java.util.logging.*;

/**
 *
 * @author Luca Marturana <luca@draios.com>
 */
public class Application {
    private final static Logger LOGGER = Logger.getLogger(Application.class.getName());
    private static final ObjectMapper mapper = new ObjectMapper();

    static {
        mapper.disable(SerializationFeature.FLUSH_AFTER_WRITE_VALUE);
        mapper.configure(JsonGenerator.Feature.AUTO_CLOSE_TARGET, false);
    }
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        LogManager.getLogManager().reset();
        Logger globalLogger = Logger.getLogger("");
        ConsoleHandler console = new ConsoleHandler();
        console.setFormatter(new LogJsonFormatter());
        globalLogger.setLevel(Level.FINER);
        globalLogger.addHandler(console);

        try {
            Application app = new Application();
            app.mainLoop();
        } catch (IOException ex) {
            LOGGER.severe("IOException on main thread: " + ex.getMessage());
            System.exit(1);
        }
    }

    private HashMap<Integer, MonitoredVM> vms;
    private Config config;

    private Application() throws FileNotFoundException {
        vms = new HashMap<Integer, MonitoredVM>();

        config = new Config();
    }

    private void mainLoop() throws IOException {
        Scanner scanner = new Scanner(System.in);
        while (true)
        {
            String cmd_data = scanner.nextLine();
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
            cleanup();
        }
    }

    private void cleanup() {
        Set<Integer> activePids = JvmstatVM.getActiveVMs();
        for (Integer pid : vms.keySet()) {
            if (!activePids.contains(pid)) {
                LOGGER.info(String.format("Removing cached entry for pid: %d", pid.intValue()));
                vms.remove(pid);
            }
        }
    }

    private List<Map<String, Object>> getMetricsCommand() throws IOException {
        LOGGER.fine("Executing getMetrics");
        List<Map<String, Object>> vmList = new LinkedList<Map<String, Object>>();

        for (Integer pid : JvmstatVM.getActiveVMs()) {
            LOGGER.info(String.format("Found java process %s", pid.intValue()));
            Map<String, Object> vmObject = new LinkedHashMap<String, Object>();
            //Integer pid = Integer.valueOf(vmd.id());
            MonitoredVM vm = vms.get(pid);

            if (vm == null) {
                vm = new MonitoredVM(pid.intValue());

                // Configure VM name if it matches a pattern on configurations
                Map<String, String> patterns = config.getPatterns();
                for (String query : patterns.keySet()) {
                    if (vm.getName().contains(query)) {
                        vm.setName(patterns.get(query));
                        break;
                    }
                }

                // Add it to known VMs
                vms.put(pid, vm);
            }
            if (vm.isAvailable()) {
                vmObject.put("pid", pid);
                vmObject.put("name", vm.getName());

                if (vm.isAgentActive()) {
                    List<BeanQuery> default_queries = config.getDefaultBeanQueries();
                    List<BeanData> beanDataList = new LinkedList<BeanData>();
                    for (BeanQuery query : default_queries) {
                        beanDataList.addAll(vm.getMetrics(query));
                    }

                    List<BeanQuery> specific_queries = config.getBeanQueries(vm.getName());
                    for (BeanQuery query : specific_queries) {
                        beanDataList.addAll(vm.getMetrics(query));
                    }
                    vmObject.put("beans", beanDataList);
                }
                vmList.add(vmObject);
            }
        }
        return vmList;
    }
}
