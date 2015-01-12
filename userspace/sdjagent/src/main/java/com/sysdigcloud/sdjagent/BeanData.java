package com.sysdigcloud.sdjagent;

import javax.management.AttributeList;
import javax.management.ObjectName;
import javax.management.openmbean.CompositeData;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Created by luca on 12/01/15.
 */
public class BeanData {
    String name;
    Map<String, Object> attributes;

    public BeanData(ObjectName name, String[] attribute_names, AttributeList attribute_values) {
        this.name = name.getCanonicalName();
        for ( int j = 0; j < attribute_names.length; ++j)
        {
            Object attribute_value = attribute_values.get(j);
            if (attribute_value instanceof CompositeData) {
                CompositeData compositeData = (CompositeData) attribute_value;
                HashMap<String, Double> subattributes = new HashMap<String, Double>();
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
                this.attributes.put(attribute_names[j], subattributes);
            }
            else {
                try {
                    this.attributes.put(attribute_names[j], getValueAsDouble(attribute_value));
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
