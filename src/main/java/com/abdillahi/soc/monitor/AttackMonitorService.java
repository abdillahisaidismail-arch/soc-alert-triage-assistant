package com.abdillahi.soc.monitor;

import com.abdillahi.soc.model.Alert;
import com.abdillahi.soc.model.LoginAttempt;
import com.abdillahi.soc.triage.AlertScorer;
import com.abdillahi.soc.triage.TriageResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Tracks failed login attempts per source IP.
 * When an IP crosses the configured threshold within the time window,
 * builds an Alert, scores it, and returns a TriageResponse.
 */
@Service
public class AttackMonitorService {

    private static final Logger log = LoggerFactory.getLogger(AttackMonitorService.class);

    @Value("${soc.bruteforce.threshold:5}")
    private int threshold;

    @Value("${soc.bruteforce.window-seconds:60}")
    private long windowSeconds;

    /** ip -> list of recent failed attempts */
    private final Map<String, List<LoginAttempt>> attempts = new ConcurrentHashMap<>();

    /** IPs whose alert has already been fired in the current window (avoid spam) */
    private final Map<String, Long> alertedIps = new ConcurrentHashMap<>();

    /**
     * Records a failed login attempt.
     * @return a TriageResponse if the threshold is crossed, null otherwise.
     */
    public TriageResponse recordFailedLogin(String sourceIp, String username, String targetHost) {
        long now      = System.currentTimeMillis();
        long windowMs = windowSeconds * 1_000L;

        List<LoginAttempt> list = attempts.computeIfAbsent(sourceIp, k -> new ArrayList<>());
        synchronized (list) {
            list.removeIf(a -> (now - a.timestampMs) > windowMs);
            list.add(new LoginAttempt(sourceIp, username, targetHost));

            int count = list.size();
            log.info("[MONITOR] Failed login #{} from {} targeting user '{}' on {}",
                    count, sourceIp, username, targetHost);

            Long lastAlert     = alertedIps.get(sourceIp);
            boolean alreadyAlerted = lastAlert != null && (now - lastAlert) < windowMs;

            if (count >= threshold && !alreadyAlerted) {
                alertedIps.put(sourceIp, now);
                log.warn("[MONITOR] THRESHOLD REACHED for IP {} ({} attempts in {}s)",
                        sourceIp, count, windowSeconds);
                return buildTriage(sourceIp, username, targetHost, count);
            }
        }
        return null;
    }

    /** Clears tracked state for a specific IP (called after a block action). */
    public void clearIp(String sourceIp) {
        attempts.remove(sourceIp);
        alertedIps.remove(sourceIp);
        log.info("[MONITOR] Cleared tracking for IP {}", sourceIp);
    }

    // -------------------------------------------------------------------------

    private TriageResponse buildTriage(String ip, String user, String host, int count) {
        Alert alert = new Alert();
        alert.id               = "EVT-" + System.currentTimeMillis();
        alert.ruleName         = "Failed Login Brute Force";
        alert.severity         = count >= threshold * 2 ? "CRITICAL" : "HIGH";
        alert.srcIp            = ip;
        alert.user             = user;
        alert.host             = host;
        alert.category         = "auth";
        alert.assetCriticality = "HIGH";
        alert.source           = "LoginMonitor";
        alert.timestamp        = System.currentTimeMillis();

        int    score      = AlertScorer.score(alert);
        String severity   = AlertScorer.bucket(score);
        String incidentId = "INC-" + System.currentTimeMillis();

        String explanation = String.format(
                "Detected %d failed login attempts from %s targeting user '%s' on host '%s' within %ds. "
                + "Declared severity: %s. Asset criticality: HIGH. MITRE T1110 — Brute Force.",
                count, ip, user, host, windowSeconds, alert.severity);

        String recommendation = String.format(
                "Lock account '%s'. Block source IP %s at the firewall. "
                + "Check whether any successful login followed the %d failed attempts.",
                user, ip, count);

        return new TriageResponse(
                incidentId, severity, score,
                explanation, recommendation,
                "T1110 — Brute Force",
                alert);
    }
}
