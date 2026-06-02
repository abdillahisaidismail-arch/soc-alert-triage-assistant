package com.abdillahi.soc.monitor;

public record GeoIpInfo(
        String status,
        String query,
        String country,
        String city,
        String isp
) {
    public static GeoIpInfo local(String ip) {
        return new GeoIpInfo("local", ip, "Local / Private Network", "Localhost", "Loopback");
    }

    public static GeoIpInfo unknown(String ip) {
        return new GeoIpInfo("unknown", ip, "Unknown", "Unknown", "Unknown");
    }
}
