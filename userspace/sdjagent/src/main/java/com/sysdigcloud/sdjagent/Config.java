package com.sysdigcloud.sdjagent;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.yaml.snakeyaml.Yaml;

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
    private Map<String, Object> conf;
    private Yaml yaml;
    private static final ObjectMapper mapper = new ObjectMapper();
    private final static Logger LOGGER = Logger.getLogger(Config.class.getName());

    private Map<String, String> patterns;
    private List<BeanQuery> defaultBeanQueries;
    private Map<String, List<BeanQuery>> beanQueries;

    public Config() throws FileNotFoundException {
        // Load config from file
        File conf_file = new File("dragent.yaml");
        if (!conf_file.exists())
        {
            conf_file = new File("/opt/draios/bin/dragent.yaml");
        }
        FileInputStream conf_file_stream = new FileInputStream(conf_file);
        yaml = new Yaml();
        conf = (Map<String, Object>)((Map<String, Object>) yaml.load(conf_file_stream)).get("jmx");

        patterns = new HashMap<String, String>();
        for ( String key : conf.keySet())
        {
            if ( ! key.equals("default"))
            {
                patterns.put(((Map<String, String>) conf.get(key)).get("pattern"), key);
            }
        }

        defaultBeanQueries = new ArrayList<BeanQuery>();
        for (Object bean : (List<Object>) conf.get("default")) {
            try {
                defaultBeanQueries.add(mapper.convertValue(bean, BeanQuery.class));
            } catch (IllegalArgumentException ex) {
                Map<String, Object> beanAsMap = mapper.convertValue(bean, Map.class);
                LOGGER.warning("Skipping invalid query: " + beanAsMap.get("query"));
            }
        }

        beanQueries = new HashMap<String, List<BeanQuery>>();

        for(String name : conf.keySet() ) {
            if (name.equals("default")) {
                continue;
            }
            Map<String, Object> queryEntry = (Map<String, Object>)conf.get(name);
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
                beanQueries.put(name, beanQueryList);
            }
        }
    }

    public Map<String, String> getPatterns()
    {
        return patterns;
    }

    public List<BeanQuery> getDefaultBeanQueries() {

        return defaultBeanQueries;
    }

    public List<BeanQuery> getBeanQueries(String name) {

        if (beanQueries.containsKey(name)) {
            return beanQueries.get(name);
        } else {
            return new ArrayList<BeanQuery>();
        }
    }
}
