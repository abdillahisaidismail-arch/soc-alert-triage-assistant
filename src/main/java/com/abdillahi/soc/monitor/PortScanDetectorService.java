package com.abdillahi.soc.monitor;

import org.springframework.stereotype.Service;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Collectors;

@Service
public class PortScanDetectorService {

    private static final long WINDOW_MILLIS = 30_000;
    private static final long COOLDOWN_MILLIS = 60_000;
    private static final int DISTINCT_PORT_THRESHOLD = 10;

    private final GeoIpService geoIpService;
    private final ConcurrentMap<String, ScanWindow> windows = new ConcurrentHashMap<>();

    public PortScanDetectorService(GeoIpService geoIpService) {
        this.geoIpService = geoIpService;
    }

    public PortScanIncidentResponse recordProbe(String sourceIp, int port, String userAgent) {
        long now = System.currentTimeMillis();
        ScanWindow window = windows.computeIfAbsent(sourceIp, key -> new ScanWindow());

        synchronized (window) {
            window.probes.addLast(new Probe(port, now, userAgent == null ? "unknown" : userAgent));
            prune(window, now);

            Set<Integer> distinctPorts = window.probes.stream()
                    .map(Probe::port)
                    .collect(Collectors.toCollection(TreeSet::new));

            int totalProbes = window.probes.size();
            long firstSeen = window.probes.isEmpty() ? now : window.probes.getFirst().timestamp();
            long durationSeconds = Math.max(1, (now - firstSeen) / 1000);

            if (distinctPorts.size() < DISTINCT_PORT_THRESHOLD) {
                return null;
            }

            if ((now - window.lastAlertAt) < COOLDOWN_MILLIS) {
                return null;
            }

            window.lastAlertAt = now;

            GeoIpInfo geo = geoIpService.lookup(sourceIp);
            String severity = distinctPorts.size() >= 20 ? "CRITICAL" : "HIGH";
            int riskScore = Math.min(100, 55 + (distinctPorts.size() * 2) + Math.min(totalProbes, 15));

            String portsText = distinctPorts.stream()
                    .map(String::valueOf)
                    .collect(Collectors.joining(", "));

            String explanation = String.format(
                    "Source IP %s scanned %d distinct ports in %d seconds. Ports observed: %s. Origin: %s, %s. ISP: %s. User-Agent: %s. This pattern is consistent with network service scanning.",
                    sourceIp,
                    distinctPorts.size(),
                    durationSeconds,
                    portsText,
                    geo.city(),
                    geo.country(),
                    geo.isp(),
                    window.probes.getLast().userAgent()
            );

            String recommendation = String.format(
                    "Block or rate-limit source IP %s at the firewall or reverse proxy. Review exposed services on the scanned ports, validate that only required ports are reachable, and escalate if additional reconnaissance or follow-on exploitation appears.",
                    sourceIp
            );

            return new PortScanIncidentResponse(
                    "INC-" + now,
                    severity,
                    riskScore,
                    "T1046 — Network Service Scanning",
                    sourceIp,
                    geo.country(),
                    geo.city(),
                    geo.isp(),
                    List.copyOf(distinctPorts),
                    totalProbes,
                    durationSeconds,
                    explanation,
                    recommendation
            );
        }
    }

    private void prune(ScanWindow window, long now) {
        while (!window.probes.isEmpty() && (now - window.probes.getFirst().timestamp()) > WINDOW_MILLIS) {
            window.probes.removeFirst();
        }
    }

    private static final class ScanWindow {
        private final Deque<Probe> probes = new ArrayDeque<>();
        private long lastAlertAt = 0L;
    }

    private record Probe(int port, long timestamp, String userAgent) {
    }
}
