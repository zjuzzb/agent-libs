package com.sysdigcloud.sdjagent;

import com.fasterxml.jackson.annotation.JsonFilter;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.BeanPropertyWriter;
import com.fasterxml.jackson.databind.ser.PropertyWriter;
import com.fasterxml.jackson.databind.ser.impl.SimpleBeanPropertyFilter;

import javax.management.ObjectName;
import javax.management.openmbean.CompositeData;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by luca on 12/01/15.
 */
public class BeanData {
    private final ObjectName name;
    private final List<BeanAttributeData> attributes;
    static private final Pattern TOKEN_PATTERN = Pattern.compile("\\{[^}]+}");

    @SuppressWarnings("unused")
    public String getName() {
        return name.getCanonicalName();
    }

    @SuppressWarnings("unused")
    public List<BeanAttributeData> getAttributes() {
        return attributes;
    }

    public BeanData(ObjectName beanInstance) {
        this.name = beanInstance;
        this.attributes = new LinkedList<BeanAttributeData>();
    }

    private String expandAlias(String alias)
    {
        StringBuilder ret = new StringBuilder(alias.length());
        Matcher m = TOKEN_PATTERN.matcher(alias);
        int lastpos = 0;
        while(m.find())
        {
            ret.append(alias.substring(lastpos, m.start()));
            lastpos = m.end();
            String key = alias.substring(m.start()+1,m.end()-1);
            String value = name.getKeyProperty(key);
            if (value != null) {
                ret.append(value);
            }
        }
        ret.append(alias.substring(lastpos, alias.length()));
        return ret.toString();
    }

    public void addAttribute(Config.BeanAttribute attributeConf, Object attribute_value) {
        BeanAttributeData newAttribute;
        if(attributeConf.hasAlias()) {
            newAttribute = new BeanAttributeData(attributeConf.getName(), expandAlias(attributeConf.getAlias()));
        } else {
            newAttribute = new BeanAttributeData(attributeConf.getName());
        }
        newAttribute.unit = attributeConf.getUnit();
        newAttribute.scale = attributeConf.getScale();
        newAttribute.type = attributeConf.getType();
        if (attribute_value instanceof CompositeData) {
            CompositeData compositeData = (CompositeData) attribute_value;
            for ( String key : compositeData.getCompositeType().keySet())
            {
                try {
                    BeanAttributeData subattribute = new BeanAttributeData(key);
                    subattribute.setValue(parseValueAsDouble(compositeData.get(key)));
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
                newAttribute.setValue(parseValueAsDouble(attribute_value));
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
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class BeanAttributeData {

        @JsonProperty
        @SuppressWarnings("unused")
        private String name;

        @JsonProperty
        private Double value;

        private Config.BeanAttribute.Unit unit;

        private Config.BeanAttribute.Scale scale;

        @JsonProperty
        private List<BeanAttributeData> subattributes;

        private Config.BeanAttribute.Type type;

        @JsonProperty
        @SuppressWarnings("unused")
        private String alias;

        private BeanAttributeData(String name, String alias) {
            this.name = name;
            this.alias = alias;
            this.subattributes = new LinkedList<BeanAttributeData>();
        }

        private BeanAttributeData(String name) {
            this.name = name;
            this.subattributes = new LinkedList<BeanAttributeData>();
        }

        @JsonProperty("unit")
        @SuppressWarnings("unused")
        private Integer getUnitJSON() {
            if (unit != null) {
                return unit.getValue();
            } else {
                return null;
            }
        }

        @JsonProperty("scale")
        @SuppressWarnings("unused")
        private Integer getScaleJSON() {
            if (scale != null) {
                return scale.getValue();
            }
            else {
                return null;
            }
        }

        @JsonProperty("type")
        @SuppressWarnings("unused")
        public Integer getType() {
            if (type != null) {
                return type.getValue();
            } else {
                return null;
            }
        }

        private void setValue(Double value) throws NumberFormatException {
            if(value.isInfinite() || value.isNaN()) {
                throw new NumberFormatException();
            }
            this.value = value;
        }

        private void addSubAttribute(BeanAttributeData subattribute) {
            subattributes.add(subattribute);
        }

        public boolean hasData() {
            return value != null || ! subattributes.isEmpty();
        }

    }

    public static class BeanAttributeDataFilter extends SimpleBeanPropertyFilter {

        @Override
        public void serializeAsField(Object pojo, JsonGenerator jgen,
                                     SerializerProvider provider, PropertyWriter writer) throws Exception {
            BeanAttributeData beanAttributeData = (BeanAttributeData) pojo;
            if (include(writer)) {
                if (writer.getName().equals("name") || writer.getName().equals("alias") ||
                        writer.getName().equals("unit") ||
                        writer.getName().equals("scale") ||
                        writer.getName().equals("type")) {
                    writer.serializeAsField(pojo, jgen, provider);
                    return;
                }
                if(beanAttributeData.subattributes.isEmpty()) {
                    if (writer.getName().equals("value")) {
                        writer.serializeAsField(pojo, jgen, provider);
                        return;
                    }
                } else {
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
