/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package com.sysdigcloud.sdjagent;

/**
 * Since we have some deps that are compiled for JVM 7, loading Application.class
 * fails without us have any control on it if JVM version is < 7.
 * This class has a bare minimum set of dependencies, it's able to catch
 * UnsupportedClassVersionError and exit nicely
 */
public class ApplicationLoader {
    public static final double MIN_JAVA_VERSION = 1.7;

    public static void main(String[] args) {
        try {
            Application.main(args);
        }
        catch (java.lang.UnsupportedClassVersionError exc)
        {
            String msg = "Incompatible class loaded: " + exc.getMessage() +
                         " (Java version: " + System.getProperty("java.version") + ", must be >=" + MIN_JAVA_VERSION + ")";
            System.err.println("{\"pid\": 0, \"level\": \"SEVERE\", \"message\": \"" + msg + "\"}");
            System.exit(Application.MONITOR_DONT_RESTART_CODE);
        }
    }
}
