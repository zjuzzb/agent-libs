package com.sysdigcloud.sdjagent;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
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
    private final Map<String, Object> conf;
    private final Yaml yaml;
    private static final ObjectMapper mapper = new ObjectMapper();
    private static final Logger LOGGER = Logger.getLogger(Config.class.getName());
    private static final String[] configFiles = {"dragent.yaml", "dragent.default.yaml",
                                       "/opt/draios/etc/dragent.yaml", "/opt/draios/etc/dragent.default.yaml" };
    private List<BeanQuery> defaultBeanQueries;
    private List<Process> processes;

    public Config() throws FileNotFoundException {

        // Load config from file
        File conf_file = null;
        for (String configFilePath : configFiles)
        {
            conf_file = new File(configFilePath);
            if (conf_file.exists())
            {
                LOGGER.info("Using config file: " + configFilePath);
                break;
            }
        }
        
        if(conf_file == null)
        {
            throw new FileNotFoundException("Cannot find configuration file in any default path");
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
                LOGGER.warning("Skipping invalid query: " + beanAsMap.get("query") + ", reason:" + ex.getMessage());
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
                        LOGGER.warning("Skipping invalid query: " + beanAsMap.get("query") + ", reason:" + ex.getMessage());
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
        private BeanAttribute[] attributes;

        @JsonCreator
        @SuppressWarnings("unused")
        private BeanQuery(@JsonProperty("query") String query, @JsonProperty("attributes") BeanAttribute[] attributes) throws
                MalformedObjectNameException {
            this.objectName = new ObjectName(query);
            this.attributes = attributes;
        }

        public BeanAttribute[] getAttributes() {
            return attributes;
        }

        @JsonIgnore
        public ObjectName getObjectName() {
            return objectName;
        }

    }

    public static class BeanAttribute {
        public static enum Type {
            counter, rate
        }
        private String name;
        private Type type;

        @JsonCreator
        @SuppressWarnings("unused")
        private BeanAttribute(JsonNode data) {
            if(data.isTextual()) {
                this.name = data.textValue();
                this.type = Type.rate;
            } else if (data.isObject()) {
                this.name = data.get("name").textValue();
                this.type = Type.valueOf(data.get("type").textValue());
            }
        }

        public String getName() {
            return name;
        }

        public Type getType() {
            return type;
        }
    }
}
