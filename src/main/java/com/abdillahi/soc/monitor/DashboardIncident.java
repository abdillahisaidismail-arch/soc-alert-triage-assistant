package com.abdillahi.soc.monitor;

import com.abdillahi.soc.model.Alert;
import com.abdillahi.soc.triage.TriageResponse;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public record DashboardIncident(
        String incidentId,
        String attackType,
        String severity,
        int riskScore,
        String mitreTechnique,
        String sourceIp,
        String origin,
        String target,
        String summary,
        String recommendation,
        String timestamp
) {
    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public static DashboardIncident fromLogin(TriageResponse triage, GeoIpInfo geo) {
        String mitre = triage.mitreTechnique;
        String attackType = inferAttackType(mitre);

        Alert sourceAlert = triage.sourceAlert;
        String user = sourceAlert != null ? sourceAlert.user : "unknown-user";
        String host = sourceAlert != null ? sourceAlert.host : "unknown-host";
        String srcIp = sourceAlert != null ? sourceAlert.srcIp : "unknown-ip";
        String target = user + " @ " + host;

        return new DashboardIncident(
                triage.incidentId,
                attackType,
                triage.severity,
                triage.riskScore,
                mitre,
                srcIp,
                formatOrigin(geo),
                target,
                triage.explanation,
                triage.recommendation,
                LocalDateTime.now().format(TS)
        );
    }

    public static DashboardIncident fromPortScan(PortScanIncidentResponse incident) {
        return new DashboardIncident(
                incident.incidentId(),
                "Port Scan",
                incident.severity(),
                incident.riskScore(),
                incident.mitreTechnique(),
                incident.sourceIp(),
                formatOrigin(incident.city(), incident.country(), incident.isp()),
                incident.portsScanned().toString(),
                incident.explanation(),
                incident.recommendation(),
                LocalDateTime.now().format(TS)
        );
    }

    private static String inferAttackType(String mitre) {
        if (mitre == null) return "Alert";
        if (mitre.contains("T1059")) return "Malware / Command Injection";
        if (mitre.contains("T1190")) return "SQL Injection";
        if (mitre.contains("T1110.004")) return "Credential Stuffing";
        if (mitre.contains("T1110")) return "Brute Force";
        if (mitre.contains("T1046")) return "Port Scan";
        return "Alert";
    }

    private static String formatOrigin(GeoIpInfo geo) {
        if (geo == null) return "Unknown";
        return formatOrigin(geo.city(), geo.country(), geo.isp());
    }

    private static String formatOrigin(String city, String country, String isp) {
        String c = city == null || city.isBlank() ? "Unknown City" : city;
        String co = country == null || country.isBlank() ? "Unknown Country" : country;
        String i = isp == null || isp.isBlank() ? "Unknown ISP" : isp;
        return c + ", " + co + " · " + i;
    }
}
