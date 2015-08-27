package com.sysdigcloud.sdjagent;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Created by luca on 17/06/15.
 */
public class VMRequest {

    @SuppressWarnings("unused")
    @JsonCreator
    VMRequest(@JsonProperty("pid") int pid, @JsonProperty("vpid") int vpid) {
        this.pid = pid;
        this.vpid = vpid;
    }

    public VMRequest(String[] args) {
        this.pid = Integer.parseInt(args[1]);
        if (args.length > 2) {
            this.vpid = Integer.parseInt(args[2]);
        } else {
            this.vpid = this.pid;
        }
    }

    public int getPid() {
        return pid;
    }

    public int getVpid() {
        return vpid;
    }

    private final int pid;
    private final int vpid;
}
