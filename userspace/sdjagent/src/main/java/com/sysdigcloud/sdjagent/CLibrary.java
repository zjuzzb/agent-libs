package com.sysdigcloud.sdjagent;

import java.util.logging.Logger;

/**
 * Created by luca on 08/01/15.
 */
public class CLibrary {
    private final static Logger LOGGER = Logger.getLogger(CLibrary.class.getName());
    private static boolean libraryLoaded;

    static {
        try {
            System.loadLibrary("sdjagent");
            libraryLoaded = true;
        } catch ( UnsatisfiedLinkError ex) {
            LOGGER.warning("Cannot load JNI library");
        }
    }

    // Use long instead of int because
    // C interface uses uint32_t
    public static int seteuid(long euid) {
        if (libraryLoaded) {
            return real_seteuid(euid);
        } else {
            return -99;
        }
    }
    public static int setegid(long egid) {
        if (libraryLoaded) {
            return real_setegid(egid);
        } else {
            return -99;
        }
    }

    private static native int real_seteuid(long euid);
    private static native int real_setegid(long egid);

    private CLibrary() {
        // Deny create instances of this class
    }
}
