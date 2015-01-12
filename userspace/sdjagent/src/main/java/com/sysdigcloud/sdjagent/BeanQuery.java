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
    private String query;
    private String[] attributes;

    @JsonCreator
    public BeanQuery(@JsonProperty("name") String query, @JsonProperty("attributes") String[] attributes) {
        this.query = query;
        this.attributes = attributes;
    }

    public String getQuery() {
        return query;
    }

    public String[] getAttributes() {
        return attributes;
    }

    @JsonIgnore
    public ObjectName getQueryObjectName() throws MalformedObjectNameException {
        return new ObjectName(query);
    }
}
