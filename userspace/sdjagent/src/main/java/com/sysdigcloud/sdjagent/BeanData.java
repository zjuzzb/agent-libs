package com.sysdigcloud.sdjagent;

import com.fasterxml.jackson.annotation.JsonFilter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.BeanPropertyWriter;
import com.fasterxml.jackson.databind.ser.PropertyWriter;
import com.fasterxml.jackson.databind.ser.impl.SimpleBeanPropertyFilter;

import javax.management.ObjectName;
import javax.management.openmbean.CompositeData;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
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
    private final List<BeanAttributeData> attributes;

    @SuppressWarnings("unused")
    public String getName() {
        return name;
    }

    @SuppressWarnings("unused")
    public List<BeanAttributeData> getAttributes() {
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
        this.attributes = new LinkedList<BeanAttributeData>();
    }

    public void addAttribute(String name, Object attribute_value, Config.BeanAttribute.Unit unit) {
        BeanAttributeData newAttribute = new BeanAttributeData(name);
        if (attribute_value instanceof CompositeData) {
            CompositeData compositeData = (CompositeData) attribute_value;
            for ( String key : compositeData.getCompositeType().keySet())
            {
                try {
                    BeanAttributeData subattribute = new BeanAttributeData(key);
                    subattribute.setValue(parseValueAsDouble(compositeData.get(key)), unit);
                    newAttribute.addSubAttribute(subattribute);
                }
                catch ( NumberFormatException ex)
                {
                    // Skip the field in this case
                }
            }
        }
        else {
            try {
                newAttribute.setValue(parseValueAsDouble(attribute_value), unit);
            } catch (NumberFormatException ex)
            {
                // Skip the value
            }
        }
        if (newAttribute.hasData()) {
            attributes.add(newAttribute);
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

    @JsonFilter("BeanAttributeDataFilter")
    public static class BeanAttributeData {
        public enum Type {
            EMPTY, SIMPLE, NESTED
        }

        @JsonProperty
        private String name;

        @JsonProperty
        private Double value;

        private Config.BeanAttribute.Unit unit;

        @JsonProperty
        private List<BeanAttributeData> subattributes;

        private Type type;

        private BeanAttributeData(String name) {
            this.name = name;
            this.subattributes = new LinkedList<BeanAttributeData>();
            this.type = Type.EMPTY;
        }

        @JsonProperty("unit")
        @SuppressWarnings("unused")
        private int getUnitJSON() {
            return unit.getValue();
        }

        private void setValue(double value, Config.BeanAttribute.Unit unit) {
            this.value = value;
            this.unit = unit;
            this.type = Type.SIMPLE;
        }

        private void addSubAttribute(BeanAttributeData subattribute) {
            subattributes.add(subattribute);
            this.type = Type.NESTED;
        }

        public boolean hasData() {
            return value != null || ! subattributes.isEmpty();
        }

        @JsonIgnore
        public Type getType() {
            return this.type;
        }
    }

    public static class BeanAttributeDataFilter extends SimpleBeanPropertyFilter {

        @Override
        public void serializeAsField(Object pojo, JsonGenerator jgen,
                                     SerializerProvider provider, PropertyWriter writer) throws Exception {
            BeanAttributeData beanAttributeData = (BeanAttributeData) pojo;
            if (include(writer)) {
                if (writer.getName().equals("name")) {
                    writer.serializeAsField(pojo, jgen, provider);
                    return;
                }
                switch (beanAttributeData.getType()) {
                    case SIMPLE:
                        if (writer.getName().equals("value") || writer.getName().equals("unit")) {
                            writer.serializeAsField(pojo, jgen, provider);
                            return;
                        }
                        break;
                    case NESTED:
                        if (writer.getName().equals("subattributes")) {
                            writer.serializeAsField(pojo, jgen, provider);
                            return;
                        }
                }
            } else if (!jgen.canOmitFields()) { // since 2.3
                writer.serializeAsOmittedField(pojo, jgen, provider);
            }
        }

        @Override
        protected boolean include(BeanPropertyWriter writer) {
            return true;
        }

        @Override
        protected boolean include(PropertyWriter writer) {
            return true;
        }
    }
}
