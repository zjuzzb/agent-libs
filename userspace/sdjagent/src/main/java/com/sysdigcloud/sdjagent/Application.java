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
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;


import javax.management.MalformedObjectNameException;
import javax.management.ObjectName;
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
    private static final double JAVA_VERSION;
    private static final double MIN_JAVA_VERSION = 1.6;
    private static final int MONITOR_DONT_RESTART_CODE = 17;
    private static final String HELP_TEXT = "Available commands:\n" +
            "getMetrics <pid> <vpid> - Get metrics from specified JVM, metrics are configure on dragent.yaml\n" +
            "availableMetrics <pid> <vpid> - Print all available beans from specified JVM, " +
                    "they are printed in a similar YAML to be easily copied to conf file\n" +
            "queryMatches <query> <beanName> - Checks if a query matches a specific bean, returns yes or no\n";
    static {
        MAPPER.disable(SerializationFeature.FLUSH_AFTER_WRITE_VALUE);
        MAPPER.configure(JsonGenerator.Feature.AUTO_CLOSE_TARGET, false);
        FilterProvider filters = new SimpleFilterProvider().addFilter("BeanAttributeDataFilter", new BeanData
                .BeanAttributeDataFilter());
        MAPPER.setFilters(filters);

        String version = System.getProperty("java.version");
        int pos = version.indexOf('.');
        pos = version.indexOf('.', pos+1);
        JAVA_VERSION = Double.parseDouble(version.substring (0, pos));
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        try {
            Application app = new Application();
            LOGGER.info(String.format("Starting sdjagent with pid: %d", CLibrary.getPid()));
            LOGGER.info(String.format("Java vendor: %s", System.getProperty("java.vendor")));
            LOGGER.info(String.format("Java version: %s", System.getProperty("java.version")));
            if(JAVA_VERSION < MIN_JAVA_VERSION) {
                LOGGER.severe("Java version unsupported");
                System.exit(MONITOR_DONT_RESTART_CODE);
            }
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
        Logger appLogger = Logger.getLogger(Application.class.getPackage().getName());
        ConsoleHandler console = new ConsoleHandler();
        console.setFormatter(new LogJsonFormatter());
        appLogger.addHandler(console);

        vms = new HashMap<Integer, MonitoredVM>();
        lastVmsCleanup = 0;
        config = new Config();

        LOGGER.fine(String.format("Found custom beans for: %s", config.getProcesses().keySet().toString()));
        Level level = config.getLogLevel();
        console.setLevel(level);
        appLogger.setLevel(level);
    }

    private void runWithArgs(String[] args) throws IOException {
        final String command = args[0];
        if(command.equals("getVMHandle") && args.length > 1) {
            final VMRequest request = new VMRequest(args);
            request.setSkipUidAndGid(true);
            final MonitoredVM vm = new MonitoredVM(request);
            final Map<String, Object> vmInfo = new HashMap<String, Object>();
            vmInfo.put("available", vm.isAvailable());
            if (vm.isAvailable()) {
                vmInfo.put("name", vm.getName());
                vmInfo.put("address", vm.getAddress());
            }
            MAPPER.writeValue(System.out, vmInfo);
        } else if (command.equals("availableMetrics") && args.length > 1) {
            final VMRequest request = new VMRequest(args);
            final MonitoredVM vm = buildMonitoredVM(request);

            DumperOptions options = new DumperOptions();
            options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
            Yaml yaml = new Yaml(options);

            Map<String, Object> vmInfo = new LinkedHashMap<String, Object>();
            vmInfo.put("pattern", vm.getName());
            if(vm.isAvailable()) {
                vmInfo.put("beans", vm.availableMetrics());
            }

            final String dump = yaml.dump(vmInfo);
            System.out.println(dump);
        } else if (command.equals("getMetrics") && args.length > 1) {
            final VMRequest request = new VMRequest(args);
            final MonitoredVM vm = buildMonitoredVM(request);
            MAPPER.enable(SerializationFeature.INDENT_OUTPUT);
            Tracer trcMetrics = new Tracer("getMetricsCommand");
            trcMetrics.enter(null);
            MAPPER.writeValue(System.out, vm.getMetrics(trcMetrics));
            trcMetrics.exit(null);
        } else if (command.equals("queryMatches") && args.length > 2) {
            try {
                final ObjectName query = new ObjectName(args[1]);
                final ObjectName beanName = new ObjectName(args[2]);
                if(query.apply(beanName)) {
                    System.out.print("yes");
                } else {
                    System.out.print("no");
                }
            } catch (MalformedObjectNameException e) {
                LOGGER.severe("Invalid bean query or name");
            }
        } else {
            System.out.print(HELP_TEXT);
        }
        System.out.println();
        System.out.flush();
    }

    private void mainLoop() throws IOException {
        PosixQueue inqueue = new PosixQueue("/sdc_sdjagent_in", PosixQueue.Direction.RECEIVE);
        PosixQueue outqueue = new PosixQueue("/sdc_sdjagent_out", PosixQueue.Direction.SEND);

        Runtime runtime = Runtime.getRuntime();
        while (true)
        {
            System.err.print(String.format("HB,%d,%d,%d\n", CLibrary.getPid(),
                                    runtime.totalMemory()/1024, System.currentTimeMillis()/1000));
            System.err.flush();
            String cmd_data = inqueue.receive(1);
            if(cmd_data != null) {
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
                    response_obj.put("body", vmList);
                    String response = MAPPER.writeValueAsString(response_obj);
                    outqueue.send(response);
                    LOGGER.fine("End getMetrics command");
                }
                // Cleanup
                if(System.currentTimeMillis() - lastVmsCleanup > VMS_CLEANUP_INTERVAL) {
                    cleanup(requestedVMs);
                    lastVmsCleanup = System.currentTimeMillis();
                }
            }
        }
    }

    private void cleanup(List<VMRequest> requestedVMs) {
        Tracer trcClean = new Tracer("cleanup");
        trcClean.enter(new ArrayList<NameValue>(Arrays.asList(new NameValue("vmSize", Integer.toString(requestedVMs.size())))));
        Set<Integer> activePids = new HashSet<Integer>();
        for (VMRequest requestedVM : requestedVMs) {
            activePids.add(requestedVM.getPid());
        }
        Iterator<Integer> vmsIt = vms.keySet().iterator();
        while (vmsIt.hasNext()) {
            Integer pid = vmsIt.next();
            if (!activePids.contains(pid)) {
                Tracer trcVm = trcClean.span("virtualMachine");
                trcVm.enter(new ArrayList<NameValue>(Arrays.asList(new NameValue("pid", Integer.toString(pid.intValue())))));
                LOGGER.info(String.format("Removing cached entry for pid: %d", pid.intValue()));
                // Cleanup resources on MonitoredVM before removing it
                MonitoredVM vm = vms.get(pid);
                vm.cleanUp();
                trcVm.exit(new ArrayList<NameValue>(Arrays.asList(new NameValue("name", vm.getName()))));
                vmsIt.remove();
            }
        }
        trcClean.exit(null);
    }

    private List<Map<String, Object>> getMetricsCommand(List<VMRequest> requestedVMs) throws IOException {
        Tracer trcMetrics = new Tracer("getMetricsCommand");
        trcMetrics.enter(new ArrayList<NameValue>(Arrays.asList(new NameValue("vmRequestSize", Integer.toString(requestedVMs.size())))));
        LOGGER.fine("Executing getMetrics");
        final List<Map<String, Object>> vmList = new LinkedList<Map<String, Object>>();

        for (VMRequest request : requestedVMs) {
            final Map<String, Object> vmObject = new LinkedHashMap<String, Object>();
            MonitoredVM vm = vms.get(request.getPid());

            Tracer trcVm = trcMetrics.span("virtualMachine");
            trcVm.enter(new ArrayList<NameValue>(Arrays.asList(new NameValue("pid", Integer.toString(request.getPid())))));
            if (vm == null) {
                vm = buildMonitoredVM(request);
                // Add it to known VMs
                vms.put(request.getPid(), vm);
            }

            if (vm.isAvailable()) {
                vmObject.put("pid", request.getPid());
                vmObject.put("name", vm.getName());

                Tracer trcBeans = trcVm.span("getBeans");
                trcBeans.enter(null);
                List<BeanData> beanDataList = vm.getMetrics(trcBeans);
                trcBeans.exit(new ArrayList<NameValue>(Arrays.asList(new NameValue("size", Integer.toString(beanDataList.size())))));
                vmObject.put("beans", beanDataList);
                vmList.add(vmObject);
                trcVm.exit(new ArrayList<NameValue>(Arrays.asList(new NameValue("name", vm.getName()))));
            }
            else
                trcVm.exit(new ArrayList<NameValue>(Arrays.asList(new NameValue("name", "n/a"))));
        }
        trcMetrics.exit(new ArrayList<NameValue>(Arrays.asList(new NameValue("vmResultSize", Integer.toString(vmList.size())))));
        return vmList;
    }

    private MonitoredVM buildMonitoredVM(VMRequest request) {
        final MonitoredVM vm = new MonitoredVM(request);
        vm.addQueries(config.getDefaultBeanQueries());
        // Configure VM name if it matches a pattern on configurations
        if(vm.isAvailable()) {
            Map<String, Config.Process> processes = config.getProcesses();
            for (Map.Entry<String, Config.Process> config : processes.entrySet()) {
                if (vm.getName().contains(config.getValue().getPattern())) {
                    vm.setName(config.getKey());
                    vm.addQueries(config.getValue().getQueries());
                    break;
                }
            }
            LOGGER.info(String.format("Detected JVM pid=%d vpid=%d mainClass=%s jmxAddress=%s", request.getPid(),
                    request.getVpid(), vm.getName(), vm.getAddress()));
        }
        return vm;
    }
}
