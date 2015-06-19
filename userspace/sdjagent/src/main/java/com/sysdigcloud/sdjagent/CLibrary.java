package com.sysdigcloud.sdjagent;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Scanner;
import java.util.logging.Logger;

/**
 * Created by luca on 08/01/15.
 */
final public class CLibrary {
    private final static Logger LOGGER = Logger.getLogger(CLibrary.class.getName());
    private static boolean libraryLoaded;
    private static int pid;
    private static int ppid;
    private static final int initialNamespace;

    static {
        try {
            // Read pid and ppid from file instead of calling getpid() because it
            // will work event we cannot load our `libsdjagent.so` library
            FileInputStream procStatusFile = new FileInputStream("/proc/self/status");
            Scanner procStatusReader = new Scanner(procStatusFile);
            while (procStatusReader.hasNextLine()) {
                String line = procStatusReader.nextLine();
                if (line.startsWith("Pid:")) {
                    // Example:
                    // Pid:	1020
                    // Uid: <pid>
                    String[] parsed = line.split("\\s+");
                    pid = Integer.parseInt(parsed[1]);

                    // Parse also parent pid
                    line = procStatusReader.nextLine();
                    parsed = line.split("\\s+");
                    ppid = Integer.parseInt(parsed[1]);

                    break;
                }
            }
            procStatusFile.close();
        } catch (IOException ex)
        {
            LOGGER.severe(String.format("Error while reading /proc/self/status: %s", ex.getMessage()));
        }

        try {
            System.loadLibrary("sdjagentjni");
            libraryLoaded = true;
        } catch ( UnsatisfiedLinkError ex) {
            LOGGER.warning(String.format("Cannot load JNI library: %s", ex.getMessage()));
        }

        if (libraryLoaded) {
            initialNamespace = open_fd(String.format("%s/proc/self/ns/net", System.getenv("SYSDIG_HOST_ROOT")));
            // TODO: Add error if this open fails
        } else {
            initialNamespace = 0;
        }
    }

    public static int getPid() {
        return pid;
    }

    public static int getPPid() {
        return ppid;
    }

    public static long[] getUidAndGid(int pid) throws IOException {
        FileInputStream procStatusFile = new FileInputStream(String.format("/proc/%d/status", pid));
        Scanner procStatusReader = new Scanner(procStatusFile);
        long[] result = new long[2];
        while (procStatusReader.hasNextLine())
        {
            String line = procStatusReader.nextLine();
            if (line.startsWith("Uid:")) {
                // Example:
                // Uid:	102	102	102	102
                // Uid: <real> <effective> <saved> <filesystem>
                String[] uids = line.split("\\s+");
                result[0] = Long.parseLong(uids[2]);
                String groupLine = procStatusReader.nextLine();
                String[] gids = groupLine.split("\\s+");
                result[1] = Long.parseLong(gids[2]);
                break;
            }
        }
        procStatusFile.close();
        return result;
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

    public static boolean setenv(String name, String value) {
        if (libraryLoaded) {
            return real_setenv(name, value, 1) == 0;
        } else {
            return false;
        }
    }

    public static boolean unsetenv(String name) {
        if (libraryLoaded) {
            return real_unsetenv(name) == 0;
        } else {
            return false;
        }
    }

    public static boolean setNamespace(int pid) {
        if (libraryLoaded) {
            String path = String.format("%s/proc/%d/ns/net", System.getenv("SYSDIG_HOST_ROOT"), pid);
            int netnsfd = open_fd(path);
            int nsret = setns(netnsfd, 0);
            close_fd(netnsfd);
            return nsret == 0;
        } else {
            return false;
        }
    }

    public static boolean setInitialNamespace() {
        if (libraryLoaded) {
            return setns(initialNamespace, 0) == 0;
        } else {
            return true;
        }
    }

    public static boolean copyToContainer(String source, int pid, String destination) {
        if (libraryLoaded) {
            return realCopyToContainer(source, pid, destination) == 0;
        } else {
            return false;
        }
    }

    public static String runOnContainer(int pid, String exe, String[] command) {
        if (libraryLoaded) {
            return realRunOnContainer(pid, exe, command);
        } else {
            return "";
        }
    }

    public static boolean rmFromContainer(int pid, String filepath) {
        if (libraryLoaded) {
            return realRmFromContainer(pid, filepath) == 0;
        } else {
            return false;
        }
    }

    // Export C function as-is and then provide a tiny wrapper to be more Java friendly
    private static native int real_seteuid(long euid);
    private static native int real_setegid(long egid);
    private static native int real_setenv(String name, String value, int overwrite);
    private static native int real_unsetenv(String name);
    private static native int setns(int fd, int type);
    private static native int open_fd(String path);
    private static native int close_fd(int fd);
    private static native int realCopyToContainer(String source, int pid, String destination);
    private static native String realRunOnContainer(int pid, String exe, String[] command);
    private static native int realRmFromContainer(int pid, String filepath);

    private CLibrary() {
        // Deny create instances of this class
    }
}
