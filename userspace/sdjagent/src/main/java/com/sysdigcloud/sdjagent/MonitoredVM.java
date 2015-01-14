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
import sun.tools.attach.HotSpotVirtualMachine;

import javax.management.*;
import java.io.*;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Luca Marturana <luca@draios.com>
 */
public class MonitoredVM {
    private final static Logger LOGGER = Logger.getLogger(MonitoredVM.class.getName());
    private Connection connection;
    private final int pid;
    private String name;
    private boolean agentActive;
    private boolean available;

    public MonitoredVM(int pid)
    {
        this.pid = pid;

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
                    // TODO: log some error
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
                LOGGER.warning(String.format("Cannot load agent on pid %d: %s", pid, e.getMessage()));
            }
        }

        if (address != null)
        {
            try {
                connection = new Connection(address);
                agentActive = true;
            } catch (IOException e) {
                LOGGER.warning(String.format("Cannot connect to JMX address %s of pid %d: %s", address, pid, e.getMessage()));
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

    public List<BeanData> getMetrics(BeanQuery query) throws IOException {
        List<BeanData> metrics = new ArrayList<BeanData>();
        MBeanServerConnection mbs = connection.getMbs();

        for ( ObjectName bean : mbs.queryNames(query.getObjectName(), null))
        {
            try {
                AttributeList attributes_list = mbs.getAttributes(bean, query.getAttributes());
                metrics.add(new BeanData(bean, query.getAttributes(), attributes_list));
            } catch (InstanceNotFoundException e) {
                LOGGER.warning(String.format("Bean %s not found on pid %d", bean.getCanonicalName(), pid));
            } catch (ReflectionException e) {
                LOGGER.warning(String.format("Cannot get attributes of Bean %s on pid %d", bean.getCanonicalName(), pid));
            }
        }

        return metrics;
    }

    private static final String LOCAL_CONNECTOR_ADDRESS_PROP =
            "com.sun.management.jmxremote.localConnectorAddress";

    private String loadManagementAgent() throws IOException {
        VirtualMachine vm;
        String vmId = String.valueOf(pid);

        // To load the agent, we need to be the same user and group
        // of the process
        long[] idInfo = getUidAndGid(pid);
        int gid_error = CLibrary.LIBC.setegid(idInfo[1]);
        int uid_error = CLibrary.LIBC.seteuid(idInfo[0]);
        if (uid_error == 0 && gid_error == 0) {
            LOGGER.info(String.format("Change uid and gid to %d:%d", idInfo[0], idInfo[1]));
        } else {
            LOGGER.warning(String.format("Cannot change uid and gid to %d:%d, errors: %d:%d", idInfo[0], idInfo[1],
                    uid_error, gid_error));
        }

        try {
            vm = VirtualMachine.attach(vmId);
        } catch (AttachNotSupportedException x) {
            throw new IOException(x);
        }
        // try to enable local JMX via jcmd command
        if (!loadManagementAgentViaJcmd(vm)) {
            // load the management agent into the target VM
            loadManagementAgentViaJar(vm);
        }

        // get the connector address
        Properties agentProps = vm.getAgentProperties();
        String address = (String) agentProps.get(LOCAL_CONNECTOR_ADDRESS_PROP);

        vm.detach();

        // Restore to uid and gid to root
        uid_error = CLibrary.LIBC.seteuid(0);
        gid_error = CLibrary.LIBC.setegid(0);
        if (uid_error == 0 && gid_error == 0) {
            LOGGER.info("Restore uid and git");
        } else {
            LOGGER.severe(String.format("Cannot restore uid and gid, errors: %d:%d", uid_error, gid_error));
        }
        return address;
    }

    private static long[] getUidAndGid(int pid) throws IOException {
        FileInputStream procStatusFile = new FileInputStream(String.format("/proc/%d/status", pid));
        Scanner procStatusReader = new Scanner(procStatusFile);
        long[] result = new long[2];
        while (procStatusReader.hasNextLine())
        {
            String line = procStatusReader.nextLine();
            if (line.startsWith("Uid:")) {
                // Example:
                // Uid:	102	102	102	102
                // Uid: <real> <effective> <saved> <filesystem>
                String[] uids = line.split("\\s+");
                result[0] = Long.parseLong(uids[2]);
                String groupLine = procStatusReader.nextLine();
                String[] gids = groupLine.split("\\s+");
                result[1] = Long.parseLong(gids[2]);
                break;
            }
        }
        return result;
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
    }
}

