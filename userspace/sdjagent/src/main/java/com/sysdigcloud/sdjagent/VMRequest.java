package com.sysdigcloud.sdjagent;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Arrays;

/**
 * Created by luca on 17/06/15.
 */
public class VMRequest {
    private final int pid;
    private final int vpid;
    private final String root;
    private final String[] args;
    private boolean skipUidAndGid;

    @SuppressWarnings("unused")
    @JsonCreator
    VMRequest(@JsonProperty("pid") int pid,
              @JsonProperty("vpid") int vpid,
              @JsonProperty("root") String root,
              @JsonProperty("args") String[] args) {
        this.skipUidAndGid = false;
        this.pid = pid;
        this.vpid = vpid;
        this.root = root;
        this.args = args;
    }

    public VMRequest(String[] args) {
        this.skipUidAndGid = false;
        this.pid = Integer.parseInt(args[1]);
        if (args.length > 2) {
            this.vpid = Integer.parseInt(args[2]);
            if (args.length > 3) {
                this.root = args[3];
                if (args.length > 4) {
                    this.args = Arrays.copyOfRange(args, 4, args.length);
                } else {
                    this.args = new String[0];
                }
            } else {
                this.root = "/";
                this.args = new String[0];
            }
        } else {
            this.vpid = this.pid;
            this.root = "/";
            this.args = new String[0];
        }
    }

    public int getPid() {
        return pid;
    }

    public int getVpid() {
        return vpid;
    }

    public String getRoot() {
        return root;
    }

    public String[] getArgs() {
        return args;
    }

    public boolean skipUidAndGid() {
        return skipUidAndGid;
    }

    public void setSkipUidAndGid(boolean skipUidAndGid) {
        this.skipUidAndGid = skipUidAndGid;
    }
}
