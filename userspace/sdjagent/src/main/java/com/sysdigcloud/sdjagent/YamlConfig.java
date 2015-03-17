package com.sysdigcloud.sdjagent;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.yaml.snakeyaml.Yaml;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.List;

/**
 * Created by luca on 12/03/15.
 */
public class YamlConfig {
    private static final Yaml yaml = new Yaml();
    private Map<String, Object> conf;
    private Map<String, Object> defaults_conf;
    private static final ObjectMapper mapper = new ObjectMapper();

    public YamlConfig(String conf_file, String defaults_file) throws FileNotFoundException {
        if (conf_file != null) {
            FileInputStream conf_file_stream = new FileInputStream(conf_file);
            conf = (Map<String, Object>) yaml.load(conf_file_stream);
        } else {
            conf = new HashMap<String, Object>();
        }
        if (defaults_file != null) {
            FileInputStream defaults_file_stream = new FileInputStream(defaults_file);
            defaults_conf = (Map<String, Object>) yaml.load(defaults_file_stream);
        } else {
            defaults_conf = new HashMap<String, Object>();
        }
    }

    public <T> T getSingle(String key, T default_value) {
        Object value = getNodeValue(conf, key);
        if (value != null)
        {
            return (T)mapper.convertValue(value, default_value.getClass());
        } else {
            value = getNodeValue(defaults_conf, key);
            if (value != null) {
                return (T)mapper.convertValue(value, default_value.getClass());
            } else {
                return default_value;
            }
        }
    }

    public <T> List<T> getMergedSequence(String key, Class<T> classType) {
        List<T> ret = new ArrayList<T>();
        Object value = getNodeValue(defaults_conf, key);
        if (value != null) {
            List<Object> values =(List<Object>) value;
            for (Object subvalue : values) {
                ret.add(mapper.convertValue(subvalue, classType));
            }
        }
        value = getNodeValue(conf, key);
        if (value != null) {
            List<Object> values =(List<Object>) value;
            for (Object subvalue : values) {
                ret.add(mapper.convertValue(subvalue, classType));
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
                ret.put(subvalue.getKey(), mapper.convertValue(subvalue.getValue(), classType));
            }
        }
        value = getNodeValue(conf, key);
        if (value != null) {
            Map<String, Object> values = (Map<String, Object>) value;
            for (Map.Entry<String, Object> subvalue : values.entrySet()) {
                ret.put(subvalue.getKey(), mapper.convertValue(subvalue.getValue(), classType));
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
