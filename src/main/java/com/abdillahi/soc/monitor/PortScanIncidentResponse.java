package com.abdillahi.soc.monitor;

import java.util.List;

public record PortScanIncidentResponse(
        String incidentId,
        String severity,
        int riskScore,
        String mitreTechnique,
        String sourceIp,
        String country,
        String city,
        String isp,
        List<Integer> portsScanned,
        int totalProbes,
        long durationSeconds,
        String explanation,
        String recommendation
) {
}
