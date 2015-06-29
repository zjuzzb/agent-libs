package com.sysdigcloud.sdjagent;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Created by luca on 17/06/15.
 */
public class VMRequest {

    @JsonCreator
    VMRequest(@JsonProperty("pid") int pid, @JsonProperty("vpid") int vpid) {
        this.pid = pid;
        this.vpid = vpid;
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
