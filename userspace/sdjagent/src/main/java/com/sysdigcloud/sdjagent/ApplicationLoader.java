/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package com.sysdigcloud.sdjagent;

import java.lang.reflect.Method;
import java.lang.reflect.InvocationTargetException;


public class ApplicationLoader {
    public static final double MIN_JAVA_VERSION = 1.7;

    public static void main(String[] args) {
        if (getJavaVersion() < MIN_JAVA_VERSION) {
            String msg = "Java 7 or later must be used. Current version is " + System.getProperty("java.version");
            System.err.println("{\"pid\": 0, \"level\": \"SEVERE\", \"message\": \"" + msg + "\"}");
            System.exit(Application.MONITOR_DONT_RESTART_CODE);
        }

        try {
            Class<?> appClass = Class.forName("com.sysdigcloud.sdjagent.Application");
            Method appMain = appClass.getMethod("main", String[].class);
            Object o = appMain.invoke(null, (Object)args);
        }
        catch (ClassNotFoundException exc) {
            String msg = "Cannot start sdjagent: " + exc.getMessage();
            System.out.println("{\"pid\": 0, \"level\": \"SEVERE\", \"message\": \"" + msg + "\"}");
            System.exit(1);
        }
        catch (NoSuchMethodException exc) {
            String msg = "Cannot start sdjagent: " + exc.getMessage();
            System.err.println("{\"pid\": 0, \"level\": \"SEVERE\", \"message\": \"" + msg + "\"}");
            System.exit(1);
        }
        catch (IllegalAccessException exc) {
            String msg = "Cannot start sdjagent: " + exc.getMessage();
            System.err.println("{\"pid\": 0, \"level\": \"SEVERE\", \"message\": \"" + msg + "\"}");
            System.exit(1);
        }
        catch (InvocationTargetException exc) {
            String msg = "Cannot start sdjagent: " + exc.getMessage();
            System.out.println("{\"pid\": 0, \"level\": \"SEVERE\", \"message\": \"" + msg + "\"}");
            System.exit(1);
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
