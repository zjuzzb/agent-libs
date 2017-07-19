/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package com.sysdigcloud.sdjagent;

import java.lang.reflect.Method;
import java.lang.reflect.InvocationTargetException;


public class ApplicationLoader {
    private static final int MIN_JAVA_VERSION = 7;

    public static void main(String[] args) {
        if (getJDKVersion() < MIN_JAVA_VERSION) {
            System.out.println("Java 7 or later must be used. Current version is " + System.getProperty("java.version"));
            System.exit(1);
        }

        try {
            Class<?> appClass = Class.forName("com.sysdigcloud.sdjagent.Application");
            Method appMain = appClass.getMethod("main", String[].class);
            Object o = appMain.invoke(null, (Object)args);
        } catch (ClassNotFoundException exc) {
            System.out.println("Cannot start sdjagent: " + exc.getMessage());
            System.exit(1);
        }
        catch (NoSuchMethodException exc) {
            System.out.println("Cannot start sdjagent: " + exc.getMessage());
            System.exit(1);
        }
        catch (IllegalAccessException exc) {
            System.out.println("Cannot start sdjagent: " + exc.getMessage());
            System.exit(1);
        }
        catch (InvocationTargetException exc) {
            System.out.println("Cannot start sdjagent: " + exc.getMessage());
            System.exit(1);
        }
        catch (java.lang.UnsupportedClassVersionError exc)
        {
            System.out.println("Incompatible class loaded: " + exc.getMessage());
            System.exit(1);
        }
    }

    public static int getJDKVersion() {
        final char VERSION_SEPARATOR = '.';
        String javaVersion = System.getProperty("java.version");
        int majorVersionDot = javaVersion.indexOf(VERSION_SEPARATOR);
        int minorVersionDot = javaVersion.indexOf(VERSION_SEPARATOR, majorVersionDot + 1);
        int version = Integer.parseInt(javaVersion.substring(majorVersionDot + 1, minorVersionDot));
        return version;
    }
}
