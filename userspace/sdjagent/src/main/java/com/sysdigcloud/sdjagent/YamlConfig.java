package com.sysdigcloud.sdjagent;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.scanner.ScannerException;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.logging.Logger;

/**
 * Created by luca on 12/03/15.
 */
public class YamlConfig {
    private static final Logger LOGGER = Logger.getLogger(YamlConfig.class.getName());
    private static final Yaml yaml = new Yaml();
    private static final ObjectMapper mapper = new ObjectMapper();
    private Map<String, Object> conf;
    private Map<String, Object> defaults_conf;

    public YamlConfig(String conf_file, String defaults_file) throws FileNotFoundException {
        if (conf_file != null) {
            FileInputStream conf_file_stream = new FileInputStream(conf_file);
            try {
                conf = (Map<String, Object>) yaml.load(conf_file_stream);
            } catch (ScannerException ex) {
                LOGGER.severe(String.format("Parsing error on config file: %s, using defaults", conf_file));
                conf = new HashMap<String, Object>();
            }
        } else {
            conf = new HashMap<String, Object>();
        }
        if (defaults_file != null) {
            FileInputStream defaults_file_stream = new FileInputStream(defaults_file);
            try {
                defaults_conf = (Map<String, Object>) yaml.load(defaults_file_stream);
            } catch (ScannerException ex) {
                LOGGER.severe(String.format("Parsing error on config file: %s, using defaults", defaults_file));
                defaults_conf = new HashMap<String, Object>();
            }
        } else {
            defaults_conf = new HashMap<String, Object>();
        }
    }

    public <T> T getSingle(String key, T default_value) {
        T value = null;

        try {
            value = (T) mapper.convertValue(getNodeValue(conf, key), default_value.getClass());
        } catch (IllegalArgumentException ex) {
            LOGGER.severe(String.format("Config file error at %s", key));
        }

        if (value == null ) {
            try {
                value = (T) mapper.convertValue(getNodeValue(defaults_conf, key), default_value.getClass());
            } catch (IllegalArgumentException ex) {
                LOGGER.severe(String.format("Config file error at %s", key));
            }
        }

        if (value == null) {
            value = default_value;
        }

        return value;
    }

    public <T> List<T> getMergedSequence(String key, Class<T> classType) {
        List<T> ret = new ArrayList<T>();
        Object value = getNodeValue(defaults_conf, key);
        if (value != null) {
            List<Object> values = (List<Object>) value;
            for (Object subvalue : values) {
                try {
                    ret.add(mapper.convertValue(subvalue, classType));
                } catch (IllegalArgumentException ex) {
                    LOGGER.severe(String.format("Config file error at %d item of %s", values.lastIndexOf(subvalue), key));
                }
            }
        }
        value = getNodeValue(conf, key);
        if (value != null) {
            List<Object> values = (List<Object>) value;
            for (Object subvalue : values) {
                try {
                    ret.add(mapper.convertValue(subvalue, classType));
                } catch (IllegalArgumentException ex) {
                    LOGGER.severe(String.format("Config file error at %d item of %s", values.lastIndexOf(subvalue), key));
                }
            }
        }
        return ret;
    }

    public <T> Map<String, T> getMergedMap(String key, Class<T> classType) {
        Map<String, T> ret = new HashMap<String, T>();
        Object value = getNodeValue(defaults_conf, key);
        if (value != null) {
            Map<String, Object> values = (Map<String, Object>) value;
            for (Map.Entry<String, Object> subvalue : values.entrySet()) {
                try {
                    ret.put(subvalue.getKey(), mapper.convertValue(subvalue.getValue(), classType));
                } catch (IllegalArgumentException ex) {
                    LOGGER.severe(String.format("Config file error at: %s.%s", key, subvalue.getKey()));
                }
            }
        }
        value = getNodeValue(conf, key);
        if (value != null) {
            Map<String, Object> values = (Map<String, Object>) value;
            for (Map.Entry<String, Object> subvalue : values.entrySet()) {
                try {
                    ret.put(subvalue.getKey(), mapper.convertValue(subvalue.getValue(), classType));
                } catch (IllegalArgumentException ex) {
                    LOGGER.severe(String.format("Config file error at: %s.%s", key, subvalue.getKey()));
                }
            }
        }
        return ret;
    }

    private static Object getNodeValue(Map<String, Object> root, String key) {
        String[] keys = key.split("\\.");

        Object ret = root.get(keys[0]);
        for (int j = 1; j < keys.length && ret instanceof Map; ++j) {
            ret = ((Map<String, Object>)ret).get(keys[j]);
        }
        return ret;
    }
}
