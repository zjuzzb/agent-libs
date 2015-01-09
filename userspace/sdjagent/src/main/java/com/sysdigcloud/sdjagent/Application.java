/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sysdigcloud.sdjagent;

import com.sun.tools.attach.VirtualMachine;
import com.sun.tools.attach.VirtualMachineDescriptor;
import sun.jvmstat.monitor.MonitorException;

import javax.management.*;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Scanner;

/**
 *
 * @author Luca Marturana <luca@draios.com>
 */
public class Application {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws IOException, MalformedObjectNameException, AttributeNotFoundException, ReflectionException, InstanceNotFoundException, MBeanException, MonitorException, URISyntaxException, IntrospectionException
    {
        // TODO code application logic here
        Application app = new Application();
        app.getMetricsCommand();
    }

    private HashMap<Integer, MonitoredVM> vms;

    private Application()
    {
        // TODO: clean no more active pids sometime
        // TODO: add conffile get
        vms = new HashMap<Integer, MonitoredVM>();
    }

    private void mainLoop() throws IOException, MalformedObjectNameException, AttributeNotFoundException, ReflectionException, InstanceNotFoundException, MBeanException, MonitorException, URISyntaxException, IntrospectionException
    {
        Scanner scanner = new Scanner(System.in);
        while (true)
        {
            String cmd = scanner.nextLine();
            if (cmd.equals("getMetrics"))
            {
                getMetricsCommand();
            }
        }
    }

    private void getMetricsCommand() throws IOException, MalformedObjectNameException, AttributeNotFoundException, ReflectionException, InstanceNotFoundException, MBeanException, MonitorException, URISyntaxException, IntrospectionException
    {
        for (VirtualMachineDescriptor vmd : VirtualMachine.list())
        {
            int pid = Integer.parseInt(vmd.id());
            MonitoredVM vm = vms.get(pid);
            if (vm == null)
            {
                vm = new MonitoredVM(pid);
                vms.put(pid, vm);
            }

            if (vm.isAgentActive())
            {
                // TODO: extract metrics, use vm.getName() to lookup on config
                System.out.println(vm.getMetrics(new ArrayList<String>()));
            }
        }
        //TODO: may be a good point to clean not more useful object from vms
    }
}
