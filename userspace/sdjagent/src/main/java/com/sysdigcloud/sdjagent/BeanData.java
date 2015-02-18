package com.sysdigcloud.sdjagent;

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
    private final String name;
    private final Map<String, Object> attributes;

    @SuppressWarnings("unused")
    public String getName() {
        return name;
    }

    @SuppressWarnings("unused")
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    /*
    public BeanData(ObjectName beanInstance, AttributeList attribute_values) {
        this.name = beanInstance.getCanonicalName();
        this.attributes = new LinkedHashMap<String, Object>();
        for ( Attribute attributeObj : attribute_values.asList())
        {
            if (attributeObj == null)
            {
                LOGGER.warning(String.format("null attribute on bean %s, probably configuration error", this.name));
                continue;
            }
            addAttribute(attributeObj.getName(), attributeObj.getValue());
        }
    }*/

    public BeanData(ObjectName beanInstance) {
        this.name = beanInstance.getCanonicalName();
        this.attributes = new LinkedHashMap<String, Object>();
    }

    public void addAttribute(String name, Object attribute_value) {
        if (attribute_value instanceof CompositeData) {
            CompositeData compositeData = (CompositeData) attribute_value;
            Map<String, Double> subattributes = new LinkedHashMap<String, Double>();
            for ( String key : compositeData.getCompositeType().keySet())
            {
                try {
                    subattributes.put(key, parseValueAsDouble(compositeData.get(key)));
                }
                catch ( NumberFormatException ex)
                {
                    // Skip the field in this case
                }
            }
            this.attributes.put(name, subattributes);
        }
        else {
            try {
                this.attributes.put(name, parseValueAsDouble(attribute_value));
            } catch (NumberFormatException ex)
            {
                // Skip the value
            }
        }
    }

    // TODO: May be exported to an util class
    public static double parseValueAsDouble(Object value) {
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
