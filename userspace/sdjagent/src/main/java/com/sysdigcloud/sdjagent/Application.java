/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sysdigcloud.sdjagent;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.tools.attach.VirtualMachine;
import com.sun.tools.attach.VirtualMachineDescriptor;
import sun.jvmstat.monitor.MonitorException;

import javax.management.*;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.*;

/**
 *
 * @author Luca Marturana <luca@draios.com>
 */
public class Application {

    private static final ObjectMapper mapper = new ObjectMapper();
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
    private Config config;

    private Application() throws FileNotFoundException
    {
        // TODO: clean no more active pids sometime
        // TODO: add conffile get
        vms = new HashMap<Integer, MonitoredVM>();

        config = new Config();
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

                // Configure VM name if it matches a pattern on configurations
                Map<String, String> queries = config.getPatterns();
                for ( String query : queries.keySet())
                {
                    if (vm.getName().contains(query))
                    {
                        vm.setName(queries.get(query));
                        break;
                    }
                }

                // Add it to known VMs
                vms.put(pid, vm);
            }

            if (vm.isAgentActive())
            {
                List<BeanQuery> default_queries = config.getDefaultBeanQueries();
                for (BeanQuery query : default_queries) {
                    List<BeanData> beanDatas = vm.getMetrics(query);
                    mapper.writeValue(System.out, beanDatas);
                }
            }
        }
        //TODO: may be a good point to clean not more useful object from vms
    }
}
