package com.sysdigcloud.sdjagent;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.yaml.snakeyaml.Yaml;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.*;
import java.util.logging.Logger;

/**
 * Created by luca on 12/03/15.
 */
public class YamlConfig {
    private static final Logger LOGGER = Logger.getLogger(YamlConfig.class.getName());
    private static final Yaml YAML = new Yaml();
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private List<Map<String, Object>> roots;

    public YamlConfig(List<String> paths) throws FileNotFoundException {
        roots = new ArrayList<Map<String, Object>>();
        for(String path : paths) {
            File configFile = new File(path);
            if(configFile.exists()) {
                FileInputStream conf_file_stream = new FileInputStream(path);
                try {
                    roots.add((Map<String, Object>) YAML.load(conf_file_stream));
                } catch (Exception ex) {
                    LOGGER.severe(String.format("Parsing error on config file: %s, using defaults", path));
                }
            } else {
                LOGGER.fine(String.format("Config file %s does not exist", path));
            }
        }
    }

    public <T> T getSingle(String key, T default_value) {
        for(Map<String, Object> root : roots) {
            try {
                T value =  (T) MAPPER.convertValue(getNodeValue(root, key), default_value.getClass());
                if(value != null) {
                    return value;
                }
            } catch (IllegalArgumentException ex) {
                LOGGER.severe(String.format("Config file error at %s", key));
            }
        }
        return default_value;
    }

    public <T> List<T> getMergedSequence(String key, Class<T> classType) {
        List<T> ret = new ArrayList<T>();
        for(Map<String, Object> root : roots) {
            Object value = getNodeValue(root, key);
            if (value != null && value instanceof List) {
                List<Object> values = (List<Object>) value;
                for (Object subvalue : values) {
                    try {
                        ret.add(MAPPER.convertValue(subvalue, classType));
                    } catch (Exception ex) {
                        LOGGER.severe(String.format("Config file error at %d item of %s", values.lastIndexOf(subvalue), key));
                    }
                }
            }
        }
        return ret;
    }

    public <T> Map<String, T> getMergedMap(String key, Class<T> classType) {
        Map<String, T> ret = new HashMap<String, T>();
        ListIterator<Map<String, Object>> iterator = roots.listIterator(roots.size());

        while(iterator.hasPrevious()) {
            Map<String, Object> root = iterator.previous();
            Object value = getNodeValue(root, key);
            if (value != null && value instanceof Map) {
                Map<String, Object> values = (Map<String, Object>) value;
                for (Map.Entry<String, Object> subvalue : values.entrySet()) {
                    try {
                        ret.put(subvalue.getKey(), MAPPER.convertValue(subvalue.getValue(), classType));
                    } catch (Exception ex) {
                        LOGGER.severe(String.format("Config file error at: %s.%s", key, subvalue.getKey()));
                    }
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
