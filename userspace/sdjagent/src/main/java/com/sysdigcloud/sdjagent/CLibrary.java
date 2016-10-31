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
    static boolean libraryLoaded;
    private static int pid;
    private static int ppid;
    private static final int initialNamespace;
    private static final String hostRoot;
    private static final long mntNamespaceInode;

    static {
        if(System.getenv("SYSDIG_HOST_ROOT") != null) {
            hostRoot = System.getenv("SYSDIG_HOST_ROOT");
        } else {
            hostRoot = "";
        }

        try {
            // Read pid and ppid from file instead of calling getpid() because it
            // will work even if we cannot load our `libsdjagent.so` library
            FileInputStream procStatusFile = new FileInputStream("/proc/self/status");
            Scanner procStatusReader = new Scanner(procStatusFile);
            while (procStatusReader.hasNextLine()) {
                String line = procStatusReader.nextLine();
                if (line.startsWith("Pid:")) {
                    // Example:
                    // Pid:	1020
                    // Pid: <pid>
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

        String loadJniFlag = System.getProperty("sdjagent.loadjnilibrary");
        if(loadJniFlag == null || loadJniFlag.equals("true")) {
            try {
                System.loadLibrary("sdjagentjni");
                libraryLoaded = true;
            } catch ( UnsatisfiedLinkError ex) {
                LOGGER.warning(String.format("Cannot load JNI library: %s", ex.getMessage()));
            }
        } else {
            LOGGER.fine("sdjagent.loadjnilibrary=false, skipping JNI library");
        }

        if (libraryLoaded) {
            initialNamespace = open_fd(String.format("%s/proc/self/ns/net", hostRoot));
            if(initialNamespace < 0) {
                LOGGER.warning("Error on opening self net namespace");
            }
            mntNamespaceInode = getInodeOfFile(String.format("%s/proc/self/ns/mnt", hostRoot));
            if (mntNamespaceInode == 0) {
                LOGGER.warning("Error on getting inode of self container");
            }
        } else {
            initialNamespace = 0;
            mntNamespaceInode = 0;
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
            String path = String.format("%s/proc/%d/ns/net", hostRoot, pid);
            int netnsfd = open_fd(path);
            if(netnsfd > 0)
            {
                int nsret = setns(netnsfd, 0);
                close_fd(netnsfd);
                return nsret == 0;
            } else {
                return false;
            }
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

    public static String runOnContainer(int pid, int vpid, String exe, String[] command, String root) {
        if (libraryLoaded) {
            return realRunOnContainer(pid, vpid, exe, command, root);
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

    public static boolean isOnAnotherContainer(int pid) {
        if (libraryLoaded) {
            final String pidMntNamespacePath = String.format("%s/proc/%d/ns/mnt", hostRoot, pid);
            final long pidMntNamespaceInode = getInodeOfFile(pidMntNamespacePath);
            if (pidMntNamespaceInode > 0) {
                return pidMntNamespaceInode != mntNamespaceInode;
            } else {
                return false;
            }
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
    private static native String realRunOnContainer(int pid, int vpid, String exe, String[] command, String root);
    private static native int realRmFromContainer(int pid, String filepath);
    private static native long getInodeOfFile(String path);

    private CLibrary() {
        // Deny create instances of this class
    }
}
