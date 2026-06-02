package com.abdillahi.soc.triage;

import com.abdillahi.soc.model.Alert;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/alerts")
public class AlertController {

    /**
     * POST /api/alerts/triage
     *
     * Accepts a single Alert as JSON, runs it through AlertScorer,
     * applies MITRE mapping and context-aware recommendations,
     * and returns a TriageResponse.
     *
     * Example body:
     * {
     *   "id": "EVT-001",
     *   "ruleName": "Failed Login Brute Force",
     *   "severity": "HIGH",
     *   "host": "web-prod-01",
     *   "user": "alice",
     *   "srcIp": "192.168.1.50",
     *   "category": "auth",
     *   "assetCriticality": "HIGH"
     * }
     */
    @PostMapping("/triage")
    public ResponseEntity<TriageResponse> triage(@RequestBody Alert alert) {

        int score = AlertScorer.score(alert);
        String severity = AlertScorer.bucket(score);
        String explanation = buildExplanation(alert, score);
        String recommendation = buildRecommendation(alert, severity);
        String mitreTechnique = mapMitreTechnique(alert);

        String incidentId = (alert.id != null && !alert.id.isBlank())
                ? "INC-" + alert.id
                : "INC-" + System.currentTimeMillis();

        TriageResponse response = new TriageResponse(
                incidentId,
                severity,
                score,
                explanation,
                recommendation,
                mitreTechnique,
                alert
        );

        return ResponseEntity.ok(response);
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private String buildExplanation(Alert alert, int score) {
        StringBuilder sb = new StringBuilder();
        sb.append("Computed risk score: ").append(score).append(". ");

        String sev = safe(alert.severity);
        sb.append("Declared severity is '").append(sev).append("'");

        String rule = safe(alert.ruleName);
        if (rule.contains("MALWARE"))      sb.append("; malware rule matched (+20)");
        if (rule.contains("ADMIN LOGIN"))  sb.append("; admin login pattern detected (+10)");
        if (rule.contains("PORT SCAN"))    sb.append("; port scan activity observed (+5)");

        String asset = safe(alert.assetCriticality);
        switch (asset) {
            case "HIGH"   -> sb.append("; high-criticality asset involved (+20)");
            case "MEDIUM" -> sb.append("; medium-criticality asset involved (+10)");
            default       -> sb.append("; asset criticality not elevated");
        }

        sb.append(".");
        return sb.toString();
    }

    private String buildRecommendation(Alert alert, String severity) {
        String rule = safe(alert.ruleName);
        String host = alert.host != null ? alert.host : "unknown host";
        String user = alert.user != null ? alert.user : "unknown user";
        String ip   = alert.srcIp != null ? alert.srcIp : "unknown IP";

        if (rule.contains("MALWARE") || rule.contains("BACKDOOR")) {
            return "Isolate host '" + host + "' immediately. Run a full forensic scan and check for lateral movement to adjacent systems.";
        }
        if (rule.contains("CREDENTIAL STUFFING")) {
            return "Force password reset for account '" + user + "'. Block IP " + ip + ". Enable MFA if not already active.";
        }
        if (rule.contains("BRUTE") || rule.contains("FAILED LOGIN")) {
            return "Lock account '" + user + "'. Block source IP " + ip + ". Verify whether any successful login followed the failed attempts.";
        }
        if (rule.contains("PORT SCAN")) {
            return "Add IP " + ip + " to the watchlist. No immediate action required — monitor for follow-up exploitation attempts.";
        }
        if (rule.contains("SQL") || rule.contains("INJECTION") || rule.contains("EXPLOIT")) {
            return "Review web application logs for host '" + host + "'. Consider WAF rule tuning and audit exposed endpoints for injection vulnerabilities.";
        }
        if (rule.contains("ACCOUNT LOCKOUT") || rule.contains("LOCK")) {
            return "Investigate whether account '" + user + "' lockout is legitimate or adversary-induced. Review admin activity logs.";
        }
        if (rule.contains("ADMIN LOGIN") || rule.contains("PRIVILEGE")) {
            return "Verify admin access by '" + user + "' from " + ip + " is authorised. If unexpected, disable account and escalate.";
        }

        return switch (severity) {
            case "CRITICAL" -> "Escalate immediately to Tier 3. Isolate affected host '" + host + "' and preserve forensic evidence before remediation.";
            case "HIGH"     -> "Escalate to Tier 2. Investigate within 1 hour. Block source IP " + ip + " if activity is confirmed malicious.";
            case "MEDIUM"   -> "Assign to analyst queue. Investigate within 4 hours. Correlate with other alerts from the same IP or user.";
            default         -> "Log and monitor. No immediate action required. Re-evaluate if frequency or score increases.";
        };
    }

    private String mapMitreTechnique(Alert alert) {
        String rule     = safe(alert.ruleName);
        String category = safe(alert.category);

        if (rule.contains("CREDENTIAL STUFFING"))                      return "T1110.004 — Credential Stuffing";
        if (rule.contains("BRUTE") || rule.contains("FAILED LOGIN"))   return "T1110 — Brute Force";
        if (rule.contains("PORT SCAN") || category.contains("SCAN"))   return "T1046 — Network Service Scanning";
        if (rule.contains("SQL") || rule.contains("INJECTION")
                || rule.contains("EXPLOIT"))                            return "T1190 — Exploit Public-Facing Application";
        if (rule.contains("ACCOUNT LOCKOUT") || rule.contains("LOCK")) return "T1531 — Account Access Removal";
        if (rule.contains("MALWARE") || rule.contains("BACKDOOR"))     return "T1059 — Command and Scripting Interpreter";
        if (rule.contains("ADMIN LOGIN") || rule.contains("PRIVILEGE")) return "T1078 — Valid Accounts";

        return "T0000 — Technique Not Mapped";
    }

    private String safe(String s) {
        return s == null ? "" : s.toUpperCase();
    }
}
