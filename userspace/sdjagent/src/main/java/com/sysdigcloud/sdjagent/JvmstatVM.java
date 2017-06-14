package com.sysdigcloud.sdjagent;

import sun.jvmstat.monitor.*;

import java.net.URISyntaxException;
import java.util.*;
import java.util.logging.Logger;

/**
 * Created by luca on 09/01/15.
 */
public class JvmstatVM {
    private final static Logger LOGGER = Logger.getLogger(JvmstatVM.class.getName());
    private final MonitoredVm vm;
    private static final String DEFAULT_LOCALHOST = "127.0.0.1";

    public JvmstatVM(int pid) throws MonitorException {
        VmIdentifier vmId;
        try {
            //vmId = new VmIdentifier(String.format("file:/tmp/hsperfdata_root/%d", pid));
            vmId = new VmIdentifier(String.format("//%d", pid));
            MonitoredHost monitoredHost = MonitoredHost.getMonitoredHost(vmId);
            vm = monitoredHost.getMonitoredVm(vmId,-1);
            //vm = new FileMonitoredVm(vmId, -1);
        } catch (URISyntaxException e) {
            // This exception should be very rare
            // rename it to MonitorException to avoid to deal with it
            // on throws clause
            throw new MonitorException(e);
        } catch (NullPointerException e) {
            // This happened when running on IBM Websphere JRE
            // we are wrapping it right now
            throw new MonitorException(e);
        }
    }

    public void detach() {
        vm.detach();
    }

    private String findByName(String key) throws MonitorException {
        Monitor m = vm.findByName(key);
        if (m != null)
        {
            return (String) m.getValue();
        } else {
            return null;
        }
    }

    private List<String> findByPattern(String pattern) throws MonitorException {
        List<Monitor> monitorList = vm.findByPattern(pattern);
        List<String> monitorStrList = new ArrayList<String>(monitorList.size());
        for (Monitor monitor : monitorList) {
            monitorStrList.add(monitor.getValue().toString());
        }
        return monitorStrList;
    }

    private String getJvmArgs() throws MonitorException {
        return MonitoredVmUtil.jvmArgs(vm);
    }

    public String getMainClass() throws MonitorException {
        return MonitoredVmUtil.mainClass(vm, true);
    }

    public String getJMXAddress() throws MonitorException {
        String address = findByName("sun.management.JMXConnectorServer.address");
        if (address == null)
        {
            List<String> remoteUrls = findByPattern("sun.management.JMXConnectorServer.[0-9]+.remoteAddress"); // NOI18N
            if (remoteUrls.size() != 0)
            {
                List<String> auths = findByPattern("sun.management.JMXConnectorServer.[0-9]+.authenticate"); // NOI18N
                if ("true".equals(auths.get(0)))
                {
                    LOGGER.warning(String.format("Process with pid %d has JMX active but requires authorization, please disable it", vm.getVmIdentifier().getLocalVmId()));
                } else
                {
                    address = remoteUrls.get(0);
                }
            }
        }
        // Try to get address from JVM args
        if (address == null)
        {
            String jvmArgs = getJvmArgs();
            StringTokenizer st = new StringTokenizer(jvmArgs);
            int port = -1;
            boolean authenticate = false;
            String hostname = DEFAULT_LOCALHOST;
            while (st.hasMoreTokens()) {
                String token = st.nextToken();
                if (token.startsWith("-Dcom.sun.management.jmxremote.port=")) { // NOI18N
                    port = Integer.parseInt(token.substring(token.indexOf("=") + 1)); // NOI18N
                } else if (token.equals("-Dcom.sun.management.jmxremote.authenticate=true")) { // NOI18N
                    LOGGER.warning(String.format("Process with pid %d has JMX active but requires authorization, please disable it", vm.getVmIdentifier().getLocalVmId()));
                    authenticate = true;
                } else if (token.startsWith("-Dcom.sun.management.jmxremote.host=")) {
                    hostname = token.substring(token.indexOf("=") + 1);
                }
            }
            if (port != -1 && authenticate == false) {
                address = String.format("service:jmx:rmi:///jndi/rmi://%s:%d/jmxrmi", hostname, port);
            }
        }
        return address;
    }
}
