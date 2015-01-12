package com.sysdigcloud.sdjagent;

import sun.jvmstat.monitor.*;

import java.net.URISyntaxException;
import java.util.List;
import java.util.ArrayList;

/**
 * Created by luca on 09/01/15.
 */
public class JvmstatVM
{
    private final MonitoredVm vm;

    public JvmstatVM(int pid) throws MonitorException, URISyntaxException
    {
        VmIdentifier vmId = new VmIdentifier(String.format("//%d", pid));
        MonitoredHost monitoredHost = MonitoredHost.getMonitoredHost(vmId);
        vm = monitoredHost.getMonitoredVm(vmId,-1);
    }

    public String findByName(String key)
    {
        String value = null;
        try
        {
            Monitor m = vm.findByName(key);
            if (m != null)
            {
                value = (String) m.getValue();
            }
        }
        catch ( MonitorException ex)
        {
            // TODO: log some error
        }
        return value;
    }

    public List<String> findByPattern(String pattern)
    {
        try {
            List<Monitor> monitorList = vm.findByPattern(pattern);
            List<String> monitorStrList = new ArrayList<String>(monitorList.size());
            for (Monitor monitor : monitorList) {
                monitorStrList.add(monitor.getValue().toString());
            }
            return monitorStrList;
        } catch (MonitorException ex)
        {
            // TODO: log some error
            return null;
        }
    }

    public String getJvmArgs() {
        try
        {
            return MonitoredVmUtil.jvmArgs(vm);
        } catch (MonitorException e)
        {
            return null;
        }
    }

    public String getMainClass()
    {
        try
        {
            return MonitoredVmUtil.mainClass(vm, true);
        } catch (MonitorException e)
        {
            // TODO: add log print
            return null;
        }
    }
}
