package com.sysdigcloud.sdjagent;

import java.util.logging.Logger;

/**
 * Created by luca on 25/06/15.
 */
public class Stopwatch {
    private static final Logger LOGGER = Logger.getLogger(Stopwatch.class.getName());
    private static final boolean enabled = true;
    private final long start;
    private final String name;

    public Stopwatch(String name) {
        start = System.currentTimeMillis();
        this.name = name;
    }

    public void end() {
        if (enabled) {
            long elapsedTime = System.currentTimeMillis() - start;
            LOGGER.info(String.format("%s took %d ms", name, elapsedTime));
        }
    }
}
