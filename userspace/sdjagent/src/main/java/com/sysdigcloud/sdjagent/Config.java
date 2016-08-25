package com.sysdigcloud.sdjagent;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;

import javax.management.MalformedObjectNameException;
import javax.management.ObjectName;
import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.HashMap;
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
    private static final String ETCDIR = "/opt/draios/etc";
    private static final String[] CONFIG_FILES = {"dragent.yaml", ETCDIR + "/dragent.yaml" };
    private static final String[] DEFAULT_CONFIG_FILES = {"dragent.default.yaml", ETCDIR + "/dragent.default.yaml" };

    private List<BeanQuery> defaultBeanQueries;
    private Map<String, Process> processes;

    public Config() throws FileNotFoundException {
        List<String> configFiles = new ArrayList<String>();
        configFiles.add(getFirstAvailableFile(CONFIG_FILES));
        configFiles.add(ETCDIR + "/dragent.auto.yaml");
        configFiles.add(getFirstAvailableFile(DEFAULT_CONFIG_FILES));

        yamlConfig = new YamlConfig(configFiles);
        defaultBeanQueries = yamlConfig.getMergedSequence("jmx.default_beans", BeanQuery.class);
        if (defaultBeanQueries.isEmpty())
        {
            LOGGER.fine("jmx.default_beans is empty, probably a configuration error");
        }
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
        public enum Type {
            counter(1), gauge(2);
            private final int id;
            Type(int id) {
                this.id = id;
            }
            public int getValue() { return id; }
        }
        public enum Unit {
            NONE(0),
            SECOND(1),
            BYTE(2),
            PERCENT(3);

            private final int id;
            Unit(int id) { this.id = id; }

            public int getValue() {
                return id;
            }
        }
        public enum Scale {
            NONE(0),

            MILLI(1),
            MICRO(2),
            NANO(3),
            MINUTE(4),
            HOUR(5),
            DAY(6),

            KILO(7),
            MEGA(8),
            GIGA(9),
            TERA(10),
            KIBI(11),
            MEBI(12),
            GIBI(13),
            TEBI(14),

            PERCENT_0_1(15);

            private final int id;

            Scale(int id) { this.id = id; }

            public int getValue() { return id; }

        }

        private static class Pair<L,R> {

            private final L left;
            private final R right;

            public Pair(L left, R right) {
                this.left = left;
                this.right = right;
            }

            public L getLeft() { return left; }
            public R getRight() { return right; }

            @Override
            public int hashCode() { return left.hashCode() ^ right.hashCode(); }

            @Override
            public boolean equals(Object o) {
                if (!(o instanceof Pair)) return false;
                Pair pairo = (Pair) o;
                return this.left.equals(pairo.getLeft()) &&
                        this.right.equals(pairo.getRight());
            }

        }

        private static final Map<String, Pair<Unit, Scale>> STRING_TO_UNIT;

        static {
            STRING_TO_UNIT = new HashMap<String, Pair<Unit, Scale>>();

            STRING_TO_UNIT.put("none", new Pair<Unit, Scale>(Unit.NONE, Scale.NONE));
            STRING_TO_UNIT.put("s", new Pair<Unit, Scale>(Unit.SECOND, Scale.NONE));
            STRING_TO_UNIT.put("ms", new Pair<Unit, Scale>(Unit.SECOND, Scale.MILLI));
            STRING_TO_UNIT.put("us", new Pair<Unit, Scale>(Unit.SECOND, Scale.MICRO));
            STRING_TO_UNIT.put("ns", new Pair<Unit, Scale>(Unit.SECOND, Scale.NANO));
            STRING_TO_UNIT.put("m", new Pair<Unit, Scale>(Unit.SECOND, Scale.MINUTE));
            STRING_TO_UNIT.put("h", new Pair<Unit, Scale>(Unit.SECOND, Scale.HOUR));
            STRING_TO_UNIT.put("d", new Pair<Unit, Scale>(Unit.SECOND, Scale.DAY));

            STRING_TO_UNIT.put("B", new Pair<Unit, Scale>(Unit.BYTE, Scale.NONE));
            STRING_TO_UNIT.put("kB", new Pair<Unit, Scale>(Unit.BYTE, Scale.KILO));
            STRING_TO_UNIT.put("MB", new Pair<Unit, Scale>(Unit.BYTE, Scale.MEGA));
            STRING_TO_UNIT.put("GB", new Pair<Unit, Scale>(Unit.BYTE, Scale.GIGA));
            STRING_TO_UNIT.put("TB", new Pair<Unit, Scale>(Unit.BYTE, Scale.TERA));
            STRING_TO_UNIT.put("KiB", new Pair<Unit, Scale>(Unit.BYTE, Scale.KIBI));
            STRING_TO_UNIT.put("MiB", new Pair<Unit, Scale>(Unit.BYTE, Scale.MEBI));
            STRING_TO_UNIT.put("GiB", new Pair<Unit, Scale>(Unit.BYTE, Scale.GIBI));
            STRING_TO_UNIT.put("TiB", new Pair<Unit, Scale>(Unit.BYTE, Scale.TEBI));

            STRING_TO_UNIT.put("K", new Pair<Unit, Scale>(Unit.NONE, Scale.KILO));
            STRING_TO_UNIT.put("M", new Pair<Unit, Scale>(Unit.NONE, Scale.MEGA));
            STRING_TO_UNIT.put("G", new Pair<Unit, Scale>(Unit.NONE, Scale.GIGA));
            STRING_TO_UNIT.put("T", new Pair<Unit, Scale>(Unit.NONE, Scale.TERA));

            STRING_TO_UNIT.put("%100", new Pair<Unit, Scale>(Unit.PERCENT, Scale.NONE));
            STRING_TO_UNIT.put("%1", new Pair<Unit, Scale>(Unit.PERCENT, Scale.PERCENT_0_1));
        }

        public static Pair<Unit, Scale> getUnitInfoFromString(String s) {
            if (STRING_TO_UNIT.containsKey(s)) {
                return STRING_TO_UNIT.get(s);
            } else {
                LOGGER.warning("Wrong metric unit specified: " + s);
                return STRING_TO_UNIT.get("none");
            }
        }

        private String name;
        private Type type;
        private Unit unit;
        private Scale scale;
        private String alias;

        @JsonCreator
        @SuppressWarnings("unused")
        private BeanAttribute(JsonNode data) {
            this.type = Type.gauge;
            this.unit = Unit.NONE;
            this.scale = Scale.NONE;
            if(data.isTextual()) {
                this.name = data.textValue();
            } else if (data.isObject()) {
                this.name = data.get("name").textValue();

                if ( data.has("type")) {
                    try {
                        this.type = Type.valueOf(data.get("type").textValue().toLowerCase());
                    } catch (IllegalArgumentException ex) {
                        LOGGER.severe(String.format("Wrong type for JMX attribute %s: %s. Accepted values are: counter, gauge; using default",
                                name, data.get("type").textValue()));
                    }
                }

                if (data.has("unit")) {
                    final Pair<Unit, Scale> unitScalePair = getUnitInfoFromString(data.get("unit").asText());
                    this.unit = unitScalePair.getLeft();
                    this.scale = unitScalePair.getRight();
                }

                if (data.has("alias")) {
                    this.alias = data.get("alias").textValue();
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

        public Scale getScale() { return scale; }

        public boolean hasAlias() {
            return alias != null;
        }

        public String getAlias() {
            return alias;
        }
    }
}
