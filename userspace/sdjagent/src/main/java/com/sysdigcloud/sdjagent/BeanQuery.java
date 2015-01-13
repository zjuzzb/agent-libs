package com.sysdigcloud.sdjagent;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import javax.management.MalformedObjectNameException;
import javax.management.ObjectName;

/**
 * Created by luca on 12/01/15.
 */
public class BeanQuery {
    private ObjectName objectName;
    private String[] attributes;

    @JsonCreator
    public BeanQuery(@JsonProperty("query") String query, @JsonProperty("attributes") String[] attributes) throws
            MalformedObjectNameException {
        this.objectName = new ObjectName(query);
        this.attributes = attributes;
    }

    public String[] getAttributes() {
        return attributes;
    }

    @JsonIgnore
    public ObjectName getObjectName() {
        return objectName;
    }
}
