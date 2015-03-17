package com.sysdigcloud.tests;

import com.sysdigcloud.sdjagent.YamlConfig;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

import java.io.FileNotFoundException;
import java.util.List;
import java.util.Map;

/**
 * Created by luca on 16/03/15.
 */
public class YamlConfigTest {

    YamlConfig yamlConfig;

    @Before
    public void setUp() throws FileNotFoundException {
        String confPath = "src/test/resources/test.yaml";
        String defaultsConfPath = "src/test/resources/test.default.yaml";
        this.yamlConfig = new YamlConfig(confPath, defaultsConfPath);
    }

    @After
    public void tearDown() {
        this.yamlConfig = null;
    }

    @Test
    public void getSingle() {
        assertEquals("mystring", yamlConfig.getSingle("mykey", ""));
        assertEquals(Integer.valueOf(6666), yamlConfig.getSingle("server.port", 7890));
        assertEquals("collector-staging.sysdigcloud.com", yamlConfig.getSingle("server.address", ""));
        assertEquals(true, yamlConfig.getSingle("mybool", false));
    }

    @Test
    public void getMergedSequence() {
        List<Integer> myarray = yamlConfig.getMergedSequence("myarray", Integer.class);
        assertEquals(3, myarray.size());
    }

    @Test
    public void getMergedMap() {
        Map<String, Map> merged = yamlConfig.getMergedMap("mynested", Map.class);
        assertEquals(Integer.valueOf(78), merged.get("firstkey").get("subkey"));
        assertEquals(Integer.valueOf(40), merged.get("secondkey").get("subkey"));

        merged = yamlConfig.getMergedMap("mynestedempty", Map.class);
        assertTrue(merged.isEmpty());
    }
}
