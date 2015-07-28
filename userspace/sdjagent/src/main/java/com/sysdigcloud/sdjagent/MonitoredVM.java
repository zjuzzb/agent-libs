/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sysdigcloud.sdjagent;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.tools.attach.AgentInitializationException;
import com.sun.tools.attach.AgentLoadException;
import com.sun.tools.attach.VirtualMachine;
import sun.jvmstat.monitor.MonitorException;

import javax.management.*;
import java.io.*;
import java.util.*;
import java.util.logging.Logger;

/**
 *
 * @author Luca Marturana <luca@draios.com>
 */
public class MonitoredVM {
    private static final Logger LOGGER = Logger.getLogger(MonitoredVM.class.getName());
    private static final long BEAN_REFRESH_INTERVAL = 10 * 60 * 1000; // 10 minutes in ms
    private static final long RECONNECTION_TIMEOUT_MS = 1 * 60 * 1000; // 1 minute
    private static final int BEANS_LIMIT = 100;
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private String address;
    private Connection connection;
    private final int pid;
    private String name;
    /**
     * AgentActive means that JMX are enabled and we can get metrics from target JVM
     */
    private boolean agentActive;
    /**
     * Available means that we can get at least the mainClass from target JVM
     */
    private boolean available;
    private long lastBeanRefresh;
    private final List<Config.BeanQuery> queryList;
    private final List<BeanInstance> matchingBeans;
    private long lastDisconnectionTimestamp;
    private final boolean isOnAnotherContainer;
    
    public MonitoredVM(VMRequest request)
    {
        this.pid = request.getPid();
        this.queryList = new ArrayList<Config.BeanQuery>();
        this.lastBeanRefresh = 0;
        this.matchingBeans = new ArrayList<BeanInstance>();
        this.available = false;
        this.agentActive = false;
        this.name = "";
        this.lastDisconnectionTimestamp = 0;

        if (request.getPid() == CLibrary.getPid()) {
            this.name = "sdjagent";
            available = true;
            agentActive = false;
            isOnAnotherContainer = false;
            return;
        }

        isOnAnotherContainer = CLibrary.isOnAnotherContainer(request.getPid());
        if (isOnAnotherContainer) {
            retrieveVmInfoFromContainer(request);
        } else {
            retrieveVMInfoFromHost(request);
        }

        connect();
    }

    private void retrieveVmInfoFromContainer(VMRequest request) {
        String data = null;

        if (CLibrary.copyToContainer("/opt/draios/share/sdjagent.jar", request.getPid(), "/tmp/sdjagent.jar") &&
           CLibrary.copyToContainer("/opt/draios/lib/libsdjagentjni.so", request.getPid(), "/tmp/libsdjagentjni.so")) {
            String[] command = {"java", "-Djava.library.path=/tmp", "-jar", "/tmp/sdjagent.jar", "getVMHandle", String.valueOf(request.getVpid())};
            data = CLibrary.runOnContainer(request.getPid(), "/usr/bin/java", command);
        } else {
            // These logs are with debug priority because may happen for every short lived java process
            LOGGER.fine(String.format("Cannot copy sdjagent files on container for pid (%d:%d)", request.getPid(), request.getVpid()));
        }

        CLibrary.rmFromContainer(request.getPid(), "/tmp/sdjagent.jar");
        CLibrary.rmFromContainer(request.getPid(), "/tmp/libsdjagentjni.so");

        if (data != null && !data.isEmpty())
        {
            try {
                Map<String, Object> vmInfo = MAPPER.readValue(data, Map.class);
                if (vmInfo.containsKey("available")) {
                    this.available = (Boolean)vmInfo.get("available");
                    if (vmInfo.containsKey("name")) {
                        this.name = (String)vmInfo.get("name");
                    }
                    if (vmInfo.containsKey("address")) {
                        this.address = (String)vmInfo.get("address");
                    }
                }
            } catch (IOException ex) {
                LOGGER.severe(String.format("Wrong data from getVMHandle for process (%d:%d): %s, exception: %s",
                        request.getPid(), request.getVpid(), data, ex.getMessage()));
            }
        }
        else
        {
            LOGGER.fine(String.format("No data from getVMHandle for process (%d:%d)", request.getPid(), request
                    .getVpid()));
        }
    }

    private void retrieveVMInfoFromHost(VMRequest request) {
        // To load the agent, we need to be the same user and group
        // of the process
        boolean uidChanged = false;
        try {
            long[] idInfo = CLibrary.getUidAndGid(request.getPid());
            int gid_error = CLibrary.setegid(idInfo[1]);
            int uid_error = CLibrary.seteuid(idInfo[0]);
            if (uid_error == 0 && gid_error == 0) {
                LOGGER.fine(String.format("Change uid and gid to %d:%d", idInfo[0], idInfo[1]));
            } else {
                LOGGER.warning(String.format("Cannot change uid and gid to %d:%d, errors: %d:%d", idInfo[0], idInfo[1],
                        uid_error, gid_error));
            }
            uidChanged = true;
        } catch (IOException ex)
        {
            LOGGER.warning(String.format("Cannot read uid:gid data from process with pid %d: %s", pid, ex.getMessage()));
        }


        try {
            JvmstatVM jvmstat;
            jvmstat = new JvmstatVM(request.getPid());
            this.name = jvmstat.getMainClass();
            // Try to get local address from jvmstat
            this.address = jvmstat.getJMXAddress();
            jvmstat.detach();
            available = true;
        } catch (MonitorException e) {
            LOGGER.severe(String.format("JvmstatVM cannot attach to %d: %s", this.pid, e.getMessage()));
            return;
        }

        // Try to load agent and get address from there
        if (this.address == null)
        {
            try
            {
                this.address = loadManagementAgent(request.getPid());
            } catch (IOException e)
            {
                LOGGER.warning(String.format("Cannot load agent on process %d: %s", this.pid, e.getMessage()));
            }
        }

        if (uidChanged)
        {
            // Restore to uid and gid to root
            int uid_error = CLibrary.seteuid(0);
            int gid_error = CLibrary.setegid(0);
            if (uid_error == 0 && gid_error == 0) {
                LOGGER.fine("Restore uid and gid");
            } else {
                LOGGER.severe(String.format("Cannot restore uid and gid, errors: %d:%d", uid_error, gid_error));
            }
        }
    }

    public boolean isAvailable() {
        return available;
    }

    public boolean isAgentActive()
    {
        // After a period of inactivity retry to connect
        if (address != null && lastDisconnectionTimestamp > 0 &&
                System.currentTimeMillis() - lastDisconnectionTimestamp > RECONNECTION_TIMEOUT_MS) {
            connect();
        }
        return agentActive;
    }

    public String getName()
    {
        return name;
    }

    public void setName(String value)
    {
        this.name = value;
    }

    public String getAddress() {
        return address;
    }

    public void addQueries(List<Config.BeanQuery> queries) {
        queryList.addAll(queries);
    }

    private void refreshMatchingBeans() throws IOException {
        matchingBeans.clear();
        Set<ObjectName> allBeans = connection.getMbs().queryNames(null, null);
        for (ObjectName bean : allBeans) {
            for( Config.BeanQuery query : queryList) {
                if (query.getObjectName().apply(bean)) {
                    matchingBeans.add(new BeanInstance(bean,query.getAttributes()));
                    break;
                }
            }
            if (matchingBeans.size() >= BEANS_LIMIT) {
                break;
            }
        }
    }

    public List<BeanData> getMetrics() {
        final List<BeanData> metrics = new LinkedList<BeanData>();
        if (agentActive) {
            try {
                if(System.currentTimeMillis() - lastBeanRefresh > BEAN_REFRESH_INTERVAL) {
                    refreshMatchingBeans();
                    lastBeanRefresh = System.currentTimeMillis();
                }

                for (BeanInstance bean : matchingBeans) {
                    try {
                        BeanData beanMetrics = bean.retrieveMetrics(connection.getMbs());
                        if (!beanMetrics.getAttributes().isEmpty())
                        {
                            metrics.add(beanMetrics);
                        }
                    } catch (InstanceNotFoundException e) {
                        LOGGER.warning(String.format("Bean %s not found on process %d, forcing refresh", bean.getName().getCanonicalName(), pid));
                        lastBeanRefresh = 0;
                    } catch (ReflectionException e) {
                        LOGGER.warning(String.format("Cannot get attributes of Bean %s on process %d: %s", bean.getName().getCanonicalName(), pid, e.getMessage()));
                        lastBeanRefresh = 0;
                    } catch (SecurityException e) {
                        LOGGER.warning(String.format("Cannot get attributes of Bean %s on process %d: %s", bean.getName().getCanonicalName(), pid, e.getMessage()));
                        lastBeanRefresh = 0;
                    }
                }
            } catch (IOException ex) {
                LOGGER.warning(String.format("Process %d agent is not responding, declaring it down", pid));
                disconnect();
            }
        }
        return metrics;
    }

    private void connect() {
        if (this.address != null)
        {
            if (isOnAnotherContainer) {
                boolean namespaceChanged = CLibrary.setNamespace(pid);

                if(!namespaceChanged) {
                    LOGGER.warning(String.format("Cannot set namespace to pid: %d", pid));
                }
            }
            try {
                connection = new Connection(address);
                agentActive = true;
                lastDisconnectionTimestamp = 0;
            } catch (IOException e) {
                LOGGER.warning(String.format("Cannot connect to JMX address %s of process %d: %s", address, pid, e.getMessage()));
            }
            if (isOnAnotherContainer) {
                boolean namespaceSet = CLibrary.setInitialNamespace();
                if(!namespaceSet) {
                    LOGGER.severe("Cannot set initial namespace");
                }
            }
        }
    }

    private void disconnect() {
        lastDisconnectionTimestamp = System.currentTimeMillis();
        connection = null;
        agentActive = false;
    }

    private static final String LOCAL_CONNECTOR_ADDRESS_PROP =
            "com.sun.management.jmxremote.localConnectorAddress";

    private static String loadManagementAgent(int pid) throws IOException {
        VirtualMachine vm;
        String vmId = String.valueOf(pid);

        try {
            vm = VirtualMachine.attach(vmId);
        } catch (Throwable x) {
            throw new IOException(x);
        }
        
        // try to enable local JMX via jcmd command
        //if (!loadManagementAgentViaJcmd(vm)) {
            // load the management agent into the target VM
            loadManagementAgentViaJar(vm);
        //}

        // get the connector address
        Properties agentProps = vm.getAgentProperties();
        String address = (String) agentProps.get(LOCAL_CONNECTOR_ADDRESS_PROP);

        vm.detach();

        return address;
    }

    private static void loadManagementAgentViaJar(VirtualMachine vm) throws IOException {
        // Normally in ${java.home}/jre/lib/management-agent.jar but might
        // be in ${java.home}/lib in build environments.
        String javaHome = vm.getSystemProperties().getProperty("java.home");
        String agent = javaHome + File.separator + "jre" + File.separator + // NOI18N
                "lib" + File.separator + "management-agent.jar";    // NOI18N
        File f = new File(agent);
        if (!f.exists()) {
            agent = javaHome + File.separator + "lib" + File.separator +    // NOI18N
                    "management-agent.jar"; // NOI18N
            f = new File(agent);
            if (!f.exists()) {
                throw new IOException("Management agent not found");    // NOI18N
            }
        }

        agent = f.getCanonicalPath();
        try {
            vm.loadAgent(agent, "com.sun.management.jmxremote");    // NOI18N
        } catch (AgentLoadException x) {
            throw new IOException(x);
        } catch (AgentInitializationException x) {
            throw new IOException(x);
        }
    }

    /*
    This doesn't work with Java 1.6

    private static final String ENABLE_LOCAL_AGENT_JCMD = "ManagementAgent.start_local";
    private boolean loadManagementAgentViaJcmd(VirtualMachine vm) throws IOException {
        if (vm instanceof HotSpotVirtualMachine) {
            HotSpotVirtualMachine hsvm = (HotSpotVirtualMachine) vm;
            InputStream in = null;
            try {
                byte b[] = new byte[256];
                int n;

                in = hsvm.executeJCmd(ENABLE_LOCAL_AGENT_JCMD);
                do {
                    n = in.read(b);
                    if (n > 0) {
                        String s = new String(b, 0, n, "UTF-8");    // NOI18N
                        System.out.print(s);
                    }
                } while (n > 0);
                return true;
            } catch (IOException ex) {
                LOGGER.log(Level.INFO, "jcmd command \"" + ENABLE_LOCAL_AGENT_JCMD + "\" for PID " + pid + " failed", ex); // NOI18N
            } finally {
                if (in != null) {
                    in.close();
                }
            }
        }
        return false;
    }*/

    static private class BeanInstance {
        private ObjectName name;
        private Map<String, Config.BeanAttribute> attributesDesc;
        private String[] attributeNames;
        private Map<String, Double> counterSamples;

        private BeanInstance(ObjectName name, Config.BeanAttribute[] attributes) {
            this.name = name;
            this.attributeNames = new String[attributes.length];
            this.attributesDesc = new HashMap<String, Config.BeanAttribute>(attributes.length);
            this.counterSamples = new HashMap<String, Double>();

            for(int j = 0; j < attributes.length; ++j) {
                Config.BeanAttribute attributeDesc = attributes[j];
                attributeNames[j] = attributeDesc.getName();
                attributesDesc.put(attributeDesc.getName(), attributeDesc);
            }
        }

        private ObjectName getName() {
            return name;
        }

        private BeanData retrieveMetrics(MBeanServerConnection mbs) throws IOException, InstanceNotFoundException, ReflectionException {
            BeanData newSample = new BeanData(name);
            AttributeList attributeValues = mbs.getAttributes(name, attributeNames);
            for (Attribute attribute : attributeValues.asList()) {
                if (attribute == null)
                {
                    LOGGER.warning(String.format("null attribute on bean %s, probably configuration error", this.name));
                    continue;
                }
                final Config.BeanAttribute attributeDesc = attributesDesc.get(attribute.getName());
                if (attributeDesc.getType() == Config.BeanAttribute.Type.counter) {
                    // TODO: Counters are supported only for simple attributes right now
                    Double lastAbsoluteValue = counterSamples.get(attribute.getName());
                    Double newAbsoluteValue = BeanData.parseValueAsDouble(attribute.getValue());

                    if (lastAbsoluteValue != null) {
                        newSample.addAttribute(attributeDesc, newAbsoluteValue-lastAbsoluteValue);
                    }

                    counterSamples.put(attribute.getName(), newAbsoluteValue);
                } else {
                    newSample.addAttribute(attributeDesc, attribute.getValue());
                }
            }
            return newSample;
        }
    }
}

