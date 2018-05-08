package com.sysdigcloud.sdjagent;

import java.io.File;
import java.net.URISyntaxException;

class Prefix {
    static String getInstallPrefix() {
        try {
            final File currentJar = new File(ApplicationLoader.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            return currentJar.getParentFile().getParent();
        } catch (URISyntaxException exc) {
            String msg = "Cannot get installation root: " + exc.getMessage();
            System.err.println("{\"pid\": 0, \"level\": \"SEVERE\", \"message\": \"" + msg + "\"}");
            System.exit(Application.MONITOR_DONT_RESTART_CODE);
        }
        return ""; // should be unreachable
    }
}
