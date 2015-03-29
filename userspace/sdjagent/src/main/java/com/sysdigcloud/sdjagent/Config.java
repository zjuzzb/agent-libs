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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by luca on 12/01/15.
 */
public class Config {
    private YamlConfig yamlConfig;
    private static final Logger LOGGER = Logger.getLogger(Config.class.getName());
    private static final String[] configFiles = {"dragent.yaml", "/opt/draios/etc/dragent.yaml" };
    private static final String[] defaultConfigFiles = {"dragent.default.yaml", "/opt/draios/etc/dragent.default.yaml" };

    private List<BeanQuery> defaultBeanQueries;
    private Map<String, Process> processes;

    public Config() throws FileNotFoundException {
        String conf_file = getFirstAvailableFile(configFiles);
        String defaults_file = getFirstAvailableFile(defaultConfigFiles);

        yamlConfig = new YamlConfig(conf_file, defaults_file);
        defaultBeanQueries = yamlConfig.getMergedSequence("jmx.default_beans", BeanQuery.class);
        processes = yamlConfig.getMergedMap("jmx.per_process_beans", Process.class);
    }

    private static String getFirstAvailableFile(String[] files) throws FileNotFoundException {
        // Load config from file
        for (String configFilePath : files)
        {
            File conf_file = new File(configFilePath);
            if (conf_file.exists())
            {
                LOGGER.info("Using config file: " + configFilePath);
                return configFilePath;
            }
        }
        return null;
    }

    public Level getLogLevel() {
        String stringLevel = yamlConfig.getSingle("log.file_priority", "info");
        if ( stringLevel.equals("error")) {
            return Level.SEVERE;
        } else if (stringLevel.equals("warning")) {
            return Level.WARNING;
        } else if (stringLevel.equals("info")) {
            return Level.INFO;
        } else if (stringLevel.equals("debug")) {
            return Level.FINE;
        }
        return Level.INFO;
    }

    public List<BeanQuery> getDefaultBeanQueries() {
        return defaultBeanQueries;
    }

    public Map<String, Process> getProcesses() {
        return processes;
    }

    public static class Process {
        private String pattern;
        private List<BeanQuery> queries;

        @JsonCreator
        @SuppressWarnings("unused")
        private Process(@JsonProperty("pattern") String pattern, @JsonProperty("beans") List<BeanQuery> queries) {
            this.pattern = pattern;
            
            this.queries = new ArrayList<BeanQuery>();
            if (queries != null) {
                this.queries.addAll(queries);
            }
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
            this.type = Type.rate;
            if(data.isTextual()) {
                this.name = data.textValue();
            } else if (data.isObject()) {
                this.name = data.get("name").textValue();
                if (data.has("type")) {
                    try {
                        this.type = Type.valueOf(data.get("type").textValue().toLowerCase());
                    } catch (IllegalArgumentException ex) {
                        LOGGER.severe(String.format("Wrong type for JMX attribute %s: %s. Accepted values are: counter, rate; using default",
                                name, data.get("type").textValue()));
                    }
                }
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
