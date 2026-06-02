package com.abdillahi.soc.monitor;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;

@Service
public class GeoIpService {

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    public GeoIpService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(4))
                .build();
    }

    public GeoIpInfo lookup(String ip) {
        if (ip == null || ip.isBlank()) {
            return GeoIpInfo.unknown("unknown");
        }

        if (isLocalOrPrivate(ip)) {
            return GeoIpInfo.local(ip);
        }

        try {
            String encodedIp = URLEncoder.encode(ip, StandardCharsets.UTF_8);
            String url = "http://ip-api.com/json/" + encodedIp + "?fields=status,query,country,city,isp";
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(5))
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            Map<String, Object> body = objectMapper.readValue(response.body(), new TypeReference<>() {});

            String status = String.valueOf(body.getOrDefault("status", "unknown"));
            if (!"success".equalsIgnoreCase(status)) {
                return GeoIpInfo.unknown(ip);
            }

            return new GeoIpInfo(
                    status,
                    String.valueOf(body.getOrDefault("query", ip)),
                    String.valueOf(body.getOrDefault("country", "Unknown")),
                    String.valueOf(body.getOrDefault("city", "Unknown")),
                    String.valueOf(body.getOrDefault("isp", "Unknown"))
            );
        } catch (Exception e) {
            return GeoIpInfo.unknown(ip);
        }
    }

    private boolean isLocalOrPrivate(String ip) {
        String value = ip.trim().toLowerCase();
        return value.equals("127.0.0.1")
                || value.equals("::1")
                || value.startsWith("10.")
                || value.startsWith("192.168.")
                || value.startsWith("172.16.")
                || value.startsWith("172.17.")
                || value.startsWith("172.18.")
                || value.startsWith("172.19.")
                || value.startsWith("172.2")
                || value.startsWith("172.30.")
                || value.startsWith("172.31.")
                || value.startsWith("fc")
                || value.startsWith("fd")
                || value.startsWith("fe80");
    }
}
