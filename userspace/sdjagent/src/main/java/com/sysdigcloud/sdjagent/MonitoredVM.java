/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sysdigcloud.sdjagent;

import sun.jvmstat.monitor.MonitoredHost;
import sun.jvmstat.monitor.VmIdentifier;
import sun.management.ConnectorAddressLink;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import javax.management.MBeanServerConnection;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXServiceURL;
import java.io.IOException;
import java.util.List;

/**
 *
 * @author Luca Marturana <luca@draios.com>
 */
public class MonitoredVM {
    private JMXServiceURL jmxAddress;
    private MBeanServerConnection mbs;
    private JMXConnector connector;
    private int pid;
    private String name;
    private boolean agentActive;
    
    public MonitoredVM(int pid) throws IOException {
        String jmxUrl = ConnectorAddressLink.importFrom(pid);
        if (jmxUrl == null)
        {

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

    private sun.jvmstat.monitor.MonitoredVm getJvmstatVM()
    {
        VmIdentifier vmId = new VmIdentifier("//" + pid.toString());
        MonitoredHost monitoredHost = MonitoredHost.getMonitoredHost(vmId);
        return monitoredHost.getMonitoredVm(vmId,-1);
    }
}

