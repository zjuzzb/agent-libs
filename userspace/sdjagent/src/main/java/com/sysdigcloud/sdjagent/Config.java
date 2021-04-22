package com.sysdigcloud.sdjagent;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.databind.JsonNode;

import javax.management.MalformedObjectNameException;
import javax.management.ObjectName;
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
    private static final String ETCDIR = Prefix.getInstallPrefix() + "/etc";

    private List<BeanQuery> defaultBeanQueries;
    private Map<String, Process> processes;
    private int maxAvailabilityCheckIntervalSec;

    public Config() throws FileNotFoundException {
        List<String> configFiles = new ArrayList<String>();
        configFiles.add(ETCDIR + "/dragent.yaml");
        configFiles.add(ETCDIR + "/kubernetes/config/dragent.yaml");
        configFiles.add(ETCDIR + "/dragent.auto.yaml");
        configFiles.add(ETCDIR + "/dragent.default.yaml");

        yamlConfig = new YamlConfig(configFiles);
        defaultBeanQueries = yamlConfig.getMergedSequence("jmx.default_beans", BeanQuery.class);
        if (defaultBeanQueries.isEmpty())
        {
            LOGGER.fine("jmx.default_beans is empty, probably a configuration error");
        }
        processes = yamlConfig.getMergedMap("jmx.per_process_beans", Process.class);

        maxAvailabilityCheckIntervalSec = yamlConfig.getSingle("jmx.max_availability_check_interval_sec", 600);
    }

    /** sdjagent_parser in subprocesses_logger controls how the messages generated
     *  by sdjagent are eventually routed to draios.log file. subprocesses_logger uses
     *  a Poco::Logger with Poco:Message::Priority levels. Java doesn't understand Poco,
     *  so in sdjagent we use Java logging which has a different set of levels.
     *  Since the log levels are eventually controlled in sdjagent_parser, we really
     *  don't need to read the config here and try to control the log level in Java.
     *  Instead, we could just set Java logging to the most permissive level (FINE) and
     *  let sdjagent_parser deal with what gets logged. But that would cause a flood of IPC messages
     *  between sdjagent and subprocesses_logger, plus generate unnecessary CPU load in sdjagent_parser.
     *  So, as a performance optimization, we read the log level specified in the yaml config
     *  and set the appropriate log level in Java logging in order to generate messages at the
     *  correct level inside sdjagent.
     */

    public String getLevel(String level, List<String> componentStringLevels) {
        for (String str : componentStringLevels) {
            String[] strArr = str.split(": ", 2);
            if ((strArr.length == 2) && (strArr[0].equals("sdjagent"))) {
                level = strArr[1];
                break;
            }
        }
        return level;
	}

    public Level getLogLevel() {
        /** This function gets the dragent.yaml config for the file log file_priority
		 *  and file_priority_by_component for the component sdjagent to determine the
		 *  specified stringFileLevel.  It performs a similar action for the console_priority
		 *  and console_priority_by_component
		 *
		 *  The stringFileLevel and stringConsoleLevel are mapped to an ordinal sev value.
		 *  The most permissive sev value is used to determine the return Java logging level.
		 *
         *  Because only a single IPC channel is used for the transfer of log messages
         *  from the sdjagent to the dragent subprocess logger, we take the most permissive
         *  value of either the log file or console as the priority level we return.
         *
		 *  The mappings are defined as follows:
		 *
		 *                |       |  Java logger level
		 *  yaml config   |  sev  |  return
		 *  ==============|=======|=====================
		 *  'fatal'       |   8   |  Level.SEVERE
		 *  'critical'    |   7   |  Level.SEVERE
		 *  'error'       |   6   |  Level.SEVERE
		 *  'warning'     |   5   |  Level.WARNING
		 *  'notice'      |   4   |  Level.WARNING
		 *  'info'        |   3   |  Level.INFO
		 *  'debug'       |   2   |  Level.FINE
		 *  'trace'       |   1   |  Level.FINE
		 *  default       |   3   |  Level.INFO
		 *
		 *  Note: This map must be kept in sync with the mapping done in sdjagent_parser.
		 *
		 *  Define dictionary dict, using the Java HashMap class, and initialize it using put
		 *  for each key, value pair.
		 */
		Map<String, Integer> dict = new HashMap<String, Integer>();
            dict.put("fatal", 8);
            dict.put("critical", 7);
            dict.put("error", 6);
            dict.put("warning", 5);
            dict.put("notice", 4);
            dict.put("info", 3);
            dict.put("debug", 2);
            dict.put("trace", 1);

        String stringFileLevel = yamlConfig.getSingle("log.file_priority", "info");
        String stringConsoleLevel = yamlConfig.getSingle("log.console_priority", "info");
        List<String> componentFileStringLevels = yamlConfig.getMergedSequence("log.file_priority_by_component", String.class);
        List<String> componentConsoleStringLevels = yamlConfig.getMergedSequence("log.console_priority_by_component", String.class);
		int sev = 0;
		int fileSev = 0;
		int consoleSev = 0;
		stringFileLevel = getLevel(stringFileLevel, componentFileStringLevels);
		fileSev = dict.get(stringFileLevel);
        /** Perform similar operations to determine the consoleSev
         */
		stringConsoleLevel = getLevel(stringConsoleLevel, componentConsoleStringLevels);
		consoleSev = dict.get(stringConsoleLevel);
        /** Set the sev level to the lower, more permissive value of either the consoleSev or the fileSev
        */
		if (fileSev < consoleSev) {
            sev = fileSev;
		}
		else {
            sev = consoleSev;
		}

        /** Map the sev level we derived from the yaml config to Java logging levels
         *  Note: this map should be kept in sync with the mapping done in sdjagent_parser
         */
        if (sev >= 6) {
            return Level.SEVERE;
        } else if (sev >= 4) {
            return Level.WARNING;
        } else if (sev == 3) {
            return Level.INFO;
        } else if (sev >= 1) {
            return Level.FINE;
        }
        return Level.INFO;
    }

    public int getMaxAvailabilityCheckIntervalSec() {
        return maxAvailabilityCheckIntervalSec;
    }

    public int getSamplingRateInSeconds()
    {
        return yamlConfig.getSingle("jmx.sampling", 1);
    }

    public int getMaxBeansPerProcess() {
        return yamlConfig.getSingle("jmx.max_per_process_beans", 300);
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

        @JsonSetter("query")
        public void setQuery(String query) throws
                MalformedObjectNameException{
            this.objectName = new ObjectName(query);
        }

        @JsonSetter("attributes")
        public void setAttributes(BeanAttribute[] attributes){
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
        private Map<String,String> segmentBy;

        @JsonCreator
        @SuppressWarnings("unused")
        private BeanAttribute(JsonNode data) {
            this.type = Type.gauge;
            this.unit = Unit.NONE;
            this.scale = Scale.NONE;
            this.segmentBy = new HashMap<String, String>();
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

                if(data.has("segment_by")){
                    final JsonNode seg = data.get("segment_by");

                    for(JsonNode el : seg){
                        segmentBy.put(el.get("key").asText(), el.get("value").asText());
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

        public Map<String,String> getSegmentBy(){
            return segmentBy;
        }
    }
}
