package com.sysdigcloud.sdjagent;

import com.sun.jna.Library;
import com.sun.jna.Native;

/**
 * Created by luca on 08/01/15.
 */
public interface CLibrary extends Library {
    // Use long instead of int because
    // C interface use uint32_t

    int seteuid(long euid);
    int setegid(long egid);

    public static final CLibrary LIBC = (CLibrary) Native.loadLibrary("c", CLibrary.class);
}
