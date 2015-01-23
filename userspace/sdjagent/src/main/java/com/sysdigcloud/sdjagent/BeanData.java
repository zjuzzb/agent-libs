package com.sysdigcloud.sdjagent;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import javax.management.Attribute;
import javax.management.AttributeList;
import javax.management.ObjectName;
import javax.management.openmbean.CompositeData;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Logger;

/**
 * Created by luca on 12/01/15.
 */
public class BeanData {
    private final static Logger LOGGER = Logger.getLogger(BeanData.class.getName());
    private String name;
    private Map<String, Object> attributes;

    @SuppressWarnings("unused")
    public String getName() {
        return name;
    }

    @SuppressWarnings("unused")
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @JsonCreator
    @SuppressWarnings("unused")
    private BeanData(@JsonProperty("name") String name, @JsonProperty("attributes") Map<String, Object> attributes) {
        this.name = name;
        this.attributes = attributes;
    }

    public BeanData(ObjectName name, AttributeList attribute_values) {
        this.name = name.getCanonicalName();
        this.attributes = new LinkedHashMap<String, Object>();
        for ( Attribute attributeObj : attribute_values.asList())
        {
            if (attributeObj == null)
            {
                LOGGER.warning(String.format("null attribute on bean %s, probably configuration error", this.name));
                continue;
            }
            Object attribute_value = attributeObj.getValue();
            if (attribute_value instanceof CompositeData) {
                CompositeData compositeData = (CompositeData) attribute_value;
                Map<String, Double> subattributes = new LinkedHashMap<String, Double>();
                for ( String key : compositeData.getCompositeType().keySet())
                {
                    try {
                        subattributes.put(key, getValueAsDouble(compositeData.get(key)));
                    }
                    catch ( NumberFormatException ex)
                    {
                        // Skip the field in this case
                    }
                }
                this.attributes.put(attributeObj.getName(), subattributes);
            }
            else {
                try {
                    this.attributes.put(attributeObj.getName(), getValueAsDouble(attribute_value));
                } catch (NumberFormatException ex)
                {
                    // Skip the value
                }
            }
        }
    }

    private static double getValueAsDouble(Object value) {
        if (value instanceof String) {
            return Double.parseDouble((String) value);
        } else if (value instanceof Integer) {
            return new Double((Integer) (value));
        } else if (value instanceof AtomicInteger) {
            return new Double(((AtomicInteger) (value)).get());
        } else if (value instanceof AtomicLong) {
            Long l = ((AtomicLong) (value)).get();
            return l.doubleValue();
        } else if (value instanceof Double) {
            return (Double) value;
        } else if (value instanceof Boolean) {
            return ((Boolean) value ? 1.0 : 0.0);
        } else if (value instanceof Long) {
            Long l = new Long((Long) value);
            return l.doubleValue();
        } else if (value instanceof Number) {
            return ((Number) value).doubleValue();
        } else {
            try {
                return new Double((Double) value);
            } catch (Exception e) {
                throw new NumberFormatException();
            }
        }
    }
}
