/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sysdigcloud.sdjagent;

import com.sun.tools.attach.AgentInitializationException;
import com.sun.tools.attach.AgentLoadException;
import com.sun.tools.attach.AttachNotSupportedException;
import com.sun.tools.attach.VirtualMachine;
import sun.jvmstat.monitor.MonitorException;

import javax.management.*;
import java.io.*;
import java.lang.management.ManagementFactory;
import java.util.*;
import java.util.logging.Logger;

/**
 *
 * @author Luca Marturana <luca@draios.com>
 */
public class MonitoredVM {
    private static final Logger LOGGER = Logger.getLogger(MonitoredVM.class.getName());
    private static final long beanRefreshInterval = 10 * 60 * 1000; // 10 minutes in ms
    private static final int beansLimit = 100;

    private Connection connection;
    private MBeanServerConnection mbs;
    private final int pid;
    private String name;
    private boolean agentActive;
    private boolean available;
    private long lastBeanRefresh;
    private List<Config.BeanQuery> queryList;
    private List<BeanInstance> matchingBeans;

    public MonitoredVM(int pid, List<Config.BeanQuery> queries)
    {
        this.pid = pid;
        this.queryList = new ArrayList<Config.BeanQuery>(queries);
        this.lastBeanRefresh = 0;
        this.matchingBeans = new ArrayList<BeanInstance>();
        this.available = false;
        this.agentActive = false;
        this.name = "";

        if (pid == CLibrary.getPid()) {
            this.name = "sdjagent";
            this.mbs = ManagementFactory.getPlatformMBeanServer();
            available = true;
            agentActive = true;
            return;
        }

        // To load the agent, we need to be the same user and group
        // of the process
        boolean uidChanged = false;
        try {
            long[] idInfo = CLibrary.getUidAndGid(pid);
            int gid_error = CLibrary.setegid(idInfo[1]);
            int uid_error = CLibrary.seteuid(idInfo[0]);
            if (uid_error == 0 && gid_error == 0) {
                LOGGER.info(String.format("Change uid and gid to %d:%d", idInfo[0], idInfo[1]));
            } else {
                LOGGER.warning(String.format("Cannot change uid and gid to %d:%d, errors: %d:%d", idInfo[0], idInfo[1],
                        uid_error, gid_error));
            }
            uidChanged = true;
        } catch (IOException ex)
        {
            LOGGER.warning(String.format("Cannot read uid:gid data from process with pid %d: %s", pid, ex.getMessage()));
        }


        JvmstatVM jvmstat;
        try {
            jvmstat = new JvmstatVM(pid);
            available = true;
        } catch (MonitorException e) {
            LOGGER.severe(String.format("JvmstatVM cannot attach to %d: %s", pid, e.getMessage()));
            return;
        }

        this.name = jvmstat.getMainClass();

        // Try to get local address from jvmstat
        String address = jvmstat.findByName("sun.management.JMXConnectorServer.address");
        if (address == null)
        {
            List<String> remoteUrls = jvmstat.findByPattern("sun.management.JMXConnectorServer.[0-9]+.remoteAddress"); // NOI18N
            if (remoteUrls.size() != 0)
            {
                List<String> auths = jvmstat.findByPattern("sun.management.JMXConnectorServer.[0-9]+.authenticate"); // NOI18N
                if ("true".equals(auths.get(0)))
                {
                    LOGGER.warning(String.format("Process with pid %d has JMX active but requires authorization, please disable it", pid));
                } else
                {
                    address = remoteUrls.get(0);
                }
            }
        }
        // Try to get address from JVM args
        if (address == null)
        {
            String jvmArgs = jvmstat.getJvmArgs();
            StringTokenizer st = new StringTokenizer(jvmArgs);
            int port = -1;
            boolean authenticate = false;
            while (st.hasMoreTokens()) {
                String token = st.nextToken();
                if (token.startsWith("-Dcom.sun.management.jmxremote.port=")) { // NOI18N
                    port = Integer.parseInt(token.substring(token.indexOf("=") + 1)); // NOI18N
                } else if (token.equals("-Dcom.sun.management.jmxremote.authenticate=true")) { // NOI18N
                    authenticate = true;
                }
            }
            if (port != -1 && authenticate == false) {
                address = String.format("service:jmx:rmi:///jndi/rmi://localhost:%d/jmxrmi", port);
            }
        }

        // Try to load agent and get address from there
        if (address == null)
        {
            try
            {
                address = loadManagementAgent();
            } catch (IOException e)
            {
                LOGGER.warning(String.format("Cannot load agent on process %d: %s", pid, e.getMessage()));
            }
        }

        if (uidChanged)
        {
            // Restore to uid and gid to root
            int uid_error = CLibrary.seteuid(0);
            int gid_error = CLibrary.setegid(0);
            if (uid_error == 0 && gid_error == 0) {
                LOGGER.info("Restore uid and gid");
            } else {
                LOGGER.severe(String.format("Cannot restore uid and gid, errors: %d:%d", uid_error, gid_error));
            }
        }

        if (address != null)
        {
            try {
                connection = new Connection(address);
                mbs = connection.getMbs();
                agentActive = true;
            } catch (IOException e) {
                LOGGER.warning(String.format("Cannot connect to JMX address %s of process %d: %s", address, pid, e.getMessage()));
            }
        }
    }

    public boolean isAvailable() {
        return available;
    }
    public boolean isAgentActive()
    {
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

    public void addQueries(List<Config.BeanQuery> queries) {
        queryList.addAll(queries);
    }

    private void refreshMatchingBeans() throws IOException {
        matchingBeans.clear();
        Set<ObjectName> allBeans = mbs.queryNames(null, null);
        for (ObjectName bean : allBeans) {
            for( Config.BeanQuery query : queryList) {
                if (query.getObjectName().apply(bean)) {
                    matchingBeans.add(new BeanInstance(bean,query.getAttributes()));
                    break;
                }
            }
            if (matchingBeans.size() >= beansLimit) {
                break;
            }
        }
    }

    public List<BeanData> getMetrics() {
        final List<BeanData> metrics = new LinkedList<BeanData>();
        if (agentActive) {
            try {
                if(System.currentTimeMillis() - lastBeanRefresh > beanRefreshInterval ) {
                    refreshMatchingBeans();
                    lastBeanRefresh = System.currentTimeMillis();
                }

                for (BeanInstance bean : matchingBeans) {
                    try {
                        BeanData beanMetrics = bean.retrieveMetrics(mbs);
                        if (!beanMetrics.getAttributes().isEmpty())
                        {
                            metrics.add(beanMetrics);
                        }
                    } catch (InstanceNotFoundException e) {
                        LOGGER.warning(String.format("Bean %s not found on process %d, forcing refresh", bean.getName().getCanonicalName(), pid));
                        lastBeanRefresh = 0;
                    } catch (ReflectionException e) {
                        LOGGER.warning(String.format("Cannot get attributes of Bean %s on process %d", bean.getName().getCanonicalName(), pid));
                        lastBeanRefresh = 0;
                    }
                }
            } catch (IOException ex) {
                LOGGER.warning(String.format("Process %d agent is not responding, declaring it down", pid));
                connection = null;
                mbs = null;
                agentActive = false;
            }
        }
        return metrics;
    }

    private static final String LOCAL_CONNECTOR_ADDRESS_PROP =
            "com.sun.management.jmxremote.localConnectorAddress";

    private String loadManagementAgent() throws IOException {
        VirtualMachine vm;
        String vmId = String.valueOf(pid);

        try {
            vm = VirtualMachine.attach(vmId);
        } catch (AttachNotSupportedException x) {
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

    private void loadManagementAgentViaJar(VirtualMachine vm) throws IOException {
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
                        newSample.addAttribute(attribute.getName(), newAbsoluteValue-lastAbsoluteValue, attributeDesc.getUnit());
                    }

                    counterSamples.put(attribute.getName(), newAbsoluteValue);
                } else {
                    newSample.addAttribute(attribute.getName(), attribute.getValue(), attributeDesc.getUnit());
                }
            }
            return newSample;
        }
    }
}

