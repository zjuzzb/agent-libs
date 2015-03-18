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
import java.util.HashMap;
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
        public static enum Unit {
            NONE(0),

            SECOND(1),
            MILLISECOND(2),
            MICROSECOND(3),
            NANOSECOND(4),
            MINUTE(5),
            HOUR(6),
            DAY(7),

            BYTE(8),
            KILOBYTE(9),
            MEGABYTE(10),
            GIGABYTE(11),
            TERABYTE(12),
            KIBIBYTE(13),
            MEBIBYTE(14),
            GIBIBYTE(15),
            TEBIBYTE(16),

            KILO(17),
            MEGA(18),
            GIGA(19),
            TERA(20),

            PERCENT(21),
            PERCENT_NORM(22);

            private final int id;
            private static final Map<String, Unit> STRING_TO_UNIT;

            static {
                STRING_TO_UNIT = new HashMap<String, Unit>();

                STRING_TO_UNIT.put("s", SECOND);
                STRING_TO_UNIT.put("ms", MILLISECOND);
                STRING_TO_UNIT.put("us", MICROSECOND);
                STRING_TO_UNIT.put("ns", NANOSECOND);
                STRING_TO_UNIT.put("m", MINUTE);
                STRING_TO_UNIT.put("h", HOUR);
                STRING_TO_UNIT.put("d", DAY);

                STRING_TO_UNIT.put("B", BYTE);
                STRING_TO_UNIT.put("kB", KILOBYTE);
                STRING_TO_UNIT.put("MB", MEGABYTE);
                STRING_TO_UNIT.put("GB", GIGABYTE);
                STRING_TO_UNIT.put("TB", TERABYTE);
                STRING_TO_UNIT.put("KiB", KIBIBYTE);
                STRING_TO_UNIT.put("MiB", MEBIBYTE);
                STRING_TO_UNIT.put("GiB", GIBIBYTE);
                STRING_TO_UNIT.put("TiB", TEBIBYTE);

                STRING_TO_UNIT.put("K", KILO);
                STRING_TO_UNIT.put("M", MEGA);
                STRING_TO_UNIT.put("G", GIGA);
                STRING_TO_UNIT.put("T", TERA);

                STRING_TO_UNIT.put("%100", PERCENT);
                STRING_TO_UNIT.put("%1", PERCENT_NORM);
            }

            private Unit(int id) { this.id = id; }

            public int getValue() { return id; }

            public static Unit fromString(String s) {
                if (STRING_TO_UNIT.containsKey(s)) {
                    return STRING_TO_UNIT.get(s);
                } else {
                    return NONE;
                }
            }
        }

        private String name;
        private Type type;
        private Unit unit;

        @JsonCreator
        @SuppressWarnings("unused")
        private BeanAttribute(JsonNode data) {
            if(data.isTextual()) {
                this.name = data.textValue();
                this.type = Type.rate;
                this.unit = Unit.NONE;
            } else if (data.isObject()) {
                this.name = data.get("name").textValue();

                if ( data.has("type")) {
                    this.type = Type.valueOf(data.get("type").textValue());
                } else {
                    this.type = Type.rate;
                }

                if (data.has("unit")) {
                    this.unit = Unit.fromString(data.get("unit").asText());
                } else {
                    this.unit = Unit.NONE;
                }
            }
        }

        public String getName() {
            return name;
        }

        public Type getType() {
            return type;
        }

        public Unit getUnit() {
            return unit;
        }
    }
}
