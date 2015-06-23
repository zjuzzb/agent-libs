package com.sysdigcloud.sdjagent;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.logging.Formatter;
import java.util.logging.LogRecord;

/**
 * Created by luca on 20/01/15.
 */
public class LogJsonFormatter extends Formatter {
    private static final JsonFactory JSON_FACTORY = new JsonFactory();

    @Override
    public String format(LogRecord record) {
        ByteArrayOutputStream jsonData = new ByteArrayOutputStream();
        try {
            JsonGenerator jgen = JSON_FACTORY.createGenerator(jsonData);
            jgen.writeStartObject();
            jgen.writeNumberField("pid", CLibrary.getPid());
            jgen.writeStringField("level", record.getLevel().getName());
            jgen.writeStringField("message", record.getMessage());
            jgen.writeEndObject();
            jgen.flush();
        } catch (IOException ex) {
            // should never throw this
        }
        jsonData.write('\n');
        return jsonData.toString();
    }
}
