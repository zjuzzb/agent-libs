package com.sysdigcloud.sdjagent;

import com.sun.jna.Native;

/**
 * Created by luca on 08/01/15.
 */
public interface CLibrary {
    int seteuid(int euid);
    int setegid(int egid);

    public static final CLibrary LIBC = (CLibrary) Native.loadLibrary("c", CLibrary.class);
}
