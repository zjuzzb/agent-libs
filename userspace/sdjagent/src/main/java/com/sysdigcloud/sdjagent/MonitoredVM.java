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
import sun.jvmstat.monitor.MonitoredHost;
import sun.jvmstat.monitor.VmIdentifier;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;
import sun.tools.attach.HotSpotVirtualMachine;

import javax.management.MBeanServerConnection;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXServiceURL;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Properties;
import java.util.StringTokenizer;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Luca Marturana <luca@draios.com>
 */
public class MonitoredVM {
    private final static Logger LOGGER = Logger.getLogger(MonitoredVM.class.getName());
    private JMXServiceURL jmxAddress;
    private MBeanServerConnection mbs;
    private JMXConnector connector;
    private int pid;
    private String name;
    private boolean agentActive;
    
    public MonitoredVM(int pid) {
        this.pid = pid;

        JvmstatVM jvmstat = new JvmstatVM(pid);

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
                address = String.format("service:jmx:rmi://localhost/jndi/rmi://localhost:%d/jmxrmi", port);
            }
        }
        if (address == null)
        {
            try
            {
                address = loadManagementAgent();
            } catch (IOException e)
            {
                e.printStackTrace();
            }
        }

        if (address != null)
        {
            jmxAddress = new JMXServiceURL(address);

        }
    }

    public boolean isAgentActive()
    {
        return agentActive;
    }

    public String getName()
    {
        return name;
    }

    public Object getMetrics(List<String> metrics)
    {
        throw new NotImplementedException();
    }

    private String loadManagementAgent() throws IOException {
        VirtualMachine vm = null;
        String name = String.valueOf(pid);
        try {
            vm = VirtualMachine.attach(name);
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
                LOGGER.log(Level.INFO, "jcmd command \""+ENABLE_LOCAL_AGENT_JCMD+"\" for PID "+vmid+" failed", ex); // NOI18N
            } finally {
                if (in != null) {
                    in.close();
                }
            }
        }
        return false;
    }


    private sun.jvmstat.monitor.MonitoredVm getJvmstatVM()
    {
        VmIdentifier vmId = new VmIdentifier(String.format("//%d", pid);
        MonitoredHost monitoredHost = MonitoredHost.getMonitoredHost(vmId);
        return monitoredHost.getMonitoredVm(vmId,-1);
    }
}

