package com.sysdigcloud.sdjagent;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.yaml.snakeyaml.Yaml;

import javax.management.MalformedObjectNameException;
import javax.management.ObjectName;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Created by luca on 12/01/15.
 */
public class Config {
    private Map<String, Object> conf;
    private Yaml yaml;
    private static final ObjectMapper mapper = new ObjectMapper();
    private static final Logger LOGGER = Logger.getLogger(Config.class.getName());

    private List<BeanQuery> defaultBeanQueries;
    private List<Process> processes;

    public Config() throws FileNotFoundException {
        // Load config from file
        File conf_file = new File("dragent.yaml");
        if (!conf_file.exists()) {
            conf_file = new File("/opt/draios/etc/dragent.yaml");
            if (!conf_file.exists()) {
                conf_file = new File("/opt/draios/etc/dragent.default.yaml");
            }
        }
        FileInputStream conf_file_stream = new FileInputStream(conf_file);
        yaml = new Yaml();
        conf = (Map<String, Object>)((Map<String, Object>) yaml.load(conf_file_stream)).get("jmx");

        defaultBeanQueries = new ArrayList<BeanQuery>();
        for (Object bean : (List<Object>) conf.get("default")) {
            try {
                defaultBeanQueries.add(mapper.convertValue(bean, BeanQuery.class));
            } catch (IllegalArgumentException ex) {
                Map<String, Object> beanAsMap = mapper.convertValue(bean, Map.class);
                LOGGER.warning("Skipping invalid query: " + beanAsMap.get("query"));
            }
        }

        processes = new ArrayList<Process>();
        for(String name : conf.keySet()) {
            if (name.equals("default")) {
                continue;
            }
            Map<String, Object> queryEntry = (Map<String, Object>)conf.get(name);
            Process process = new Process();
            process.name = name;
            process.pattern = (String) queryEntry.get("pattern");

            List beansList = mapper.convertValue(queryEntry.get("beans"), List.class);
            List<BeanQuery> beanQueryList = new ArrayList<BeanQuery>();
            if (beansList != null) {
                for (Object beanQuery : beansList) {
                    try {
                        beanQueryList.add(mapper.convertValue(beanQuery, BeanQuery.class));
                    } catch (IllegalArgumentException ex)
                    {
                        Map<String, Object> beanAsMap = mapper.convertValue(beanQuery, Map.class);
                        LOGGER.warning("Skipping invalid query: " + beanAsMap.get("query"));
                    }
                }
                process.queries = beanQueryList;
            }

            processes.add(process);
        }
    }

    public List<BeanQuery> getDefaultBeanQueries() {
        return defaultBeanQueries;
    }

    public List<Process> getProcesses() {
        return processes;
    }

    public static class Process {
        private String name;
        private String pattern;
        private List<BeanQuery> queries;

        public Process() {
            this.name = "";
            this.pattern = "";
            this.queries = new ArrayList<BeanQuery>();
        }

        public String getName() {
            return name;
        }

        public String getPattern() {
            return pattern;
        }

        public List<BeanQuery> getQueries() {
            return queries;
        }
    }

    public static class BeanQuery {
        private ObjectName objectName;
        private String[] attributes;

        @JsonCreator
        @SuppressWarnings("unused")
        private BeanQuery(@JsonProperty("query") String query, @JsonProperty("attributes") String[] attributes) throws
                MalformedObjectNameException {
            this.objectName = new ObjectName(query);
            this.attributes = attributes;
        }

        public String[] getAttributes() {
            return attributes;
        }

        @JsonIgnore
        public ObjectName getObjectName() {
            return objectName;
        }

    }
}
