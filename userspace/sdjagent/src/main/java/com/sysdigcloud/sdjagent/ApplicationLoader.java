/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package com.sysdigcloud.sdjagent;

/**
 * This class has been created to avoid crashes on java < 7.
 * Since we have some deps that are compiled for JVM 7, loading Application.class
 * fails without us have any control on it. This class has a bare minimum set of dependencies,
 * it's able to catch UnsupportedClassVersionError and exit nicely
 */
public class ApplicationLoader {
    public static final double MIN_JAVA_VERSION = 1.7;

    public static void main(String[] args) {
        if (getJavaVersion() < MIN_JAVA_VERSION) {
            String msg = "Java 7 or later must be used. Current version is " + System.getProperty("java.version");
            System.err.println("{\"pid\": 0, \"level\": \"SEVERE\", \"message\": \"" + msg + "\"}");
            System.exit(Application.MONITOR_DONT_RESTART_CODE);
        }

        try {
            Application.main(args);
        }
        catch (java.lang.UnsupportedClassVersionError exc)
        {
            String msg = "Incompatible class loaded: " + exc.getMessage();
            System.err.println("{\"pid\": 0, \"level\": \"SEVERE\", \"message\": \"" + msg + "\"}");
            System.exit(Application.MONITOR_DONT_RESTART_CODE);
        }
    }

    public static double getJavaVersion() {
        String version = System.getProperty("java.version");
        int pos = version.indexOf('.');
        pos = version.indexOf('.', pos+1);
        return Double.parseDouble(version.substring (0, pos));
    }
}
