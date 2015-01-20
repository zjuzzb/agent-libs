/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sysdigcloud.sdjagent;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.sun.tools.attach.VirtualMachine;
import com.sun.tools.attach.VirtualMachineDescriptor;


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
        // TODO: Don't indent on release builds
        //mapper.enable(SerializationFeature.INDENT_OUTPUT);
        //mapper.disable(SerializationFeature.CLOSE_CLOSEABLE);
        mapper.disable(SerializationFeature.FLUSH_AFTER_WRITE_VALUE);
        mapper.configure(JsonGenerator.Feature.AUTO_CLOSE_TARGET, false);
    }
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws IOException {
        // TODO code application logic here
        LogManager.getLogManager().reset();
        Logger globalLogger = Logger.getLogger("");
        ConsoleHandler console = new ConsoleHandler();
        console.setFormatter(new LogJsonFormatter());
        globalLogger.setLevel(Level.FINER);
        globalLogger.addHandler(console);
        Application app = new Application();
        app.mainLoop();
    }

    private HashMap<Integer, MonitoredVM> vms;
    private Config config;

    private Application() throws FileNotFoundException {
        // TODO: clean no more active pids sometime
        // TODO: add conffile get
        vms = new HashMap<Integer, MonitoredVM>();

        config = new Config();
    }

    private void mainLoop() throws IOException {
        Scanner scanner = new Scanner(System.in);
        while (true)
        {
            String cmd = scanner.nextLine();
            LOGGER.fine(String.format("Received command: %s", cmd));
            if (cmd.equals("getMetrics"))
            {
                getMetricsCommand();
            }
        }
    }

    private void getMetricsCommand() throws IOException {
        LOGGER.fine("Executing getMetrics");
        List<Map<String, Object>> vmList = new LinkedList<Map<String, Object>>();
        for (VirtualMachineDescriptor vmd : VirtualMachine.list())
        {
            Map<String, Object> vmObject = new LinkedHashMap<String, Object>();
            int pid = Integer.parseInt(vmd.id());
            MonitoredVM vm = vms.get(pid);

            if (vm == null)
            {
                vm = new MonitoredVM(pid);

                // Configure VM name if it matches a pattern on configurations
                Map<String, String> patterns = config.getPatterns();
                for ( String query : patterns.keySet())
                {
                    if (vm.getName().contains(query))
                    {
                        vm.setName(patterns.get(query));
                        break;
                    }
                }

                // Add it to known VMs
                vms.put(pid, vm);
            }
            if (vm.isAvailable()) {
                vmObject.put("pid", new Integer(pid));
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
        mapper.writeValue(System.out, vmList);
        System.out.println();
        System.out.flush();
        LOGGER.fine("End getMetrics command");
        //TODO: may be a good point to clean not more useful object from vms
    }
}
