package com.sysdigcloud.sdjagent;

import com.sun.tools.attach.AgentInitializationException;
import com.sun.tools.attach.AgentLoadException;
import com.sun.tools.attach.VirtualMachine;
import sun.tools.attach.LinuxVirtualMachine;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.Properties;
import java.util.logging.Logger;

/**
 * Created by luca on 24/09/16.
 */
public class AttachAPI {
    private static final Logger LOGGER = Logger.getLogger(AttachAPI.class.getName());
    private static final String LOCAL_CONNECTOR_ADDRESS_PROP =
            "com.sun.management.jmxremote.localConnectorAddress";

    static {
        // From jdk/src/solaris/classes/sun/tools/attach/LinuxVirtualMachine.java
        // and jdk/src/solaris/native/sun/tools/attach/LinuxVirtualMachine.c
        // jdk has different code to handle LinuxThreads and NTPL based libc.
        // It assumes NTPL if it finds a newer version of glibc, using custom
        // glibc defines. On alpine linux and muslc these defines are not present
        // so it wrongly assumes the system is using LinuxThreads and AttachAPI
        // does not work.
        // Here we are fixing this flag using Java reflection, it's a "hackish"
        // way to do it but it's the simplest.
        try {
            final Field linuxThreadsField = LinuxVirtualMachine.class.getDeclaredField("isLinuxThreads");
            linuxThreadsField.setAccessible(true);
            LOGGER.fine("Previous value of LinuxVirtualMachine.isLinuxThreads=" + String.valueOf(linuxThreadsField.getBoolean(null)));
            linuxThreadsField.set(null, false);
        } catch (NoSuchFieldException e) {
            LOGGER.warning("Cannot patch LinuxVirtualMachine, NoSuchFieldException: " + e.getMessage());
        } catch (IllegalAccessException e) {
            LOGGER.warning("Cannot patch LinuxVirtualMachine, IllegalAccessException: " + e.getMessage());
        } catch (SecurityException e) {
            LOGGER.warning("Cannot patch LinuxVirtualMachine, SecurityException: " + e.getMessage());
        } catch (final UnsatisfiedLinkError e) {
            LOGGER.warning("Cannot patch LinuxVirtualMachine, UnsatisfiedLinkError: " + e.getMessage());
        } catch (final Exception e) {
            LOGGER.warning("Cannot patch LinuxVirtualMachine, Exception: " + e.getMessage());
        }
    }

    public static String loadManagementAgent(int pid) throws IOException {
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
     * This doesn't work with Java 1.6, it needs java 7 and tools.jar 7.71
     * it may be useful in the future
     */

    /* private static final String ENABLE_LOCAL_AGENT_JCMD = "ManagementAgent.start_local";
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
}
