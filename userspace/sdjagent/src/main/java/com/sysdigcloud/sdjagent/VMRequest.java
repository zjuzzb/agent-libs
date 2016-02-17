package com.sysdigcloud.sdjagent;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by luca on 17/06/15.
 */
public class VMRequest {

    @SuppressWarnings("unused")
    @JsonCreator
    VMRequest(@JsonProperty("pid") int pid,
              @JsonProperty("vpid") int vpid,
              @JsonProperty("root") String root,
              @JsonProperty("args") List<String> args) {
        this.pid = pid;
        this.vpid = vpid;
        this.root = root;
        this.args = args;
    }

    public VMRequest(String[] args) {
        this.pid = Integer.parseInt(args[1]);
        if (args.length > 2) {
            this.vpid = Integer.parseInt(args[2]);
            if (args.length > 3) {
                this.root = args[3];
            } else {
                this.root = "/";
            }
        } else {
            this.vpid = this.pid;
            this.root = "/";
        }
        this.args = new ArrayList<String>();
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

    public List<String> getArgs() {
        return args;
    }

    private final int pid;
    private final int vpid;
    private final String root;
    private final List<String> args;
}
