package com.abdillahi.soc.io;             // ✅ correct

import com.abdillahi.soc.model.Alert;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.InputStream;
import java.util.List;

public class AlertLoader {

    public static List<Alert> loadFromResource(String resourcePath) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            InputStream is = AlertLoader.class
                    .getClassLoader()
                    .getResourceAsStream(resourcePath);
            if (is == null) {
                throw new IllegalArgumentException("File not found: " + resourcePath);
            }
            return mapper.readValue(is, new TypeReference<List<Alert>>() {});
        } catch (Exception e) {
            throw new RuntimeException("Failed to load alerts: " + e.getMessage(), e);
        }
    }
}