package com.abdillahi.soc.monitor;

import com.abdillahi.soc.model.Alert;
import com.abdillahi.soc.triage.AlertScorer;
import com.abdillahi.soc.triage.TriageResponse;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;
import java.util.List;

/**
 * Serves the demo login page and processes login attempts.
 *
 * GET  /login  — renders the login form
 * POST /login  — three detection layers in order:
 *
 *   1. MALWARE / INJECTION keyword detection (instant CRITICAL, no threshold)
 *      Fires immediately when the username or password field contains
 *      known attack patterns: shell commands, SQL keywords, script paths, etc.
 *      MITRE: T1059 (Command & Scripting Interpreter) or T1190 (SQLi)
 *
 *   2. Brute-force threshold (5 failures / 60 s)
 *      Tracked per source IP by AttackMonitorService.
 *      MITRE: T1110 (Brute Force)
 *
 *   3. Plain bad-credential banner (failures below threshold)
 *
 * Demo credentials: username=admin  password=secret123
 */
@Controller
public class LoginController {

    private static final String VALID_USER = "admin";
    private static final String VALID_PASS = "secret123";

    // --- Malware / command-injection patterns ---
    private static final List<String> MALWARE_KEYWORDS = List.of(
            "cmd", "powershell", "bash", "sh ", "/bin/", "/etc/",
            "wget ", "curl ", "nc ", "netcat", "meterpreter",
            "mimikatz", "cobalt", "empire", "metasploit",
            "<script", "javascript:", "eval(", "exec(",
            "base64", "\\x", "whoami", "net user", "net localgroup"
    );

    // --- SQL injection patterns ---
    private static final List<String> SQLI_KEYWORDS = List.of(
            "' or", "\" or", "1=1", "--", ";", "union select",
            "drop table", "insert into", "xp_cmdshell", "information_schema"
    );

    private final AttackMonitorService monitor;
    private final EmailAlertService    emailService;

    public LoginController(AttackMonitorService monitor, EmailAlertService emailService) {
        this.monitor      = monitor;
        this.emailService = emailService;
    }

    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }

    @PostMapping("/login")
    public String handleLogin(
            @RequestParam String username,
            @RequestParam String password,
            HttpServletRequest request,
            Model model) {

        // 1. Valid login
        if (VALID_USER.equals(username) && VALID_PASS.equals(password)) {
            model.addAttribute("success", true);
            return "login";
        }

        String sourceIp = resolveClientIp(request);
        String combined = (username + " " + password).toLowerCase();

        // 2. Malware / command-injection keyword detected
        String malwareMatch = findMatch(combined, MALWARE_KEYWORDS);
        if (malwareMatch != null) {
            TriageResponse triage = buildKeywordTriage(
                    sourceIp, username, "auth-server-01",
                    "Malware / Command Injection Attempt",
                    "CRITICAL",
                    "T1059 — Command and Scripting Interpreter",
                    malwareMatch);
            emailService.sendIncidentAlert(triage);
            model.addAttribute("incident", triage);
            model.addAttribute("error", true);
            model.addAttribute("username", username);
            return "login";
        }

        // 3. SQL injection keyword detected
        String sqliMatch = findMatch(combined, SQLI_KEYWORDS);
        if (sqliMatch != null) {
            TriageResponse triage = buildKeywordTriage(
                    sourceIp, username, "auth-server-01",
                    "SQL Injection Attempt",
                    "HIGH",
                    "T1190 — Exploit Public-Facing Application",
                    sqliMatch);
            emailService.sendIncidentAlert(triage);
            model.addAttribute("incident", triage);
            model.addAttribute("error", true);
            model.addAttribute("username", username);
            return "login";
        }

        // 4. Brute-force threshold check
        TriageResponse triage = monitor.recordFailedLogin(sourceIp, username, "auth-server-01");
        if (triage != null) {
            emailService.sendIncidentAlert(triage);
            model.addAttribute("incident", triage);
        }

        model.addAttribute("error",    true);
        model.addAttribute("username", username);
        return "login";
    }

    // -------------------------------------------------------------------------

    private String findMatch(String input, List<String> keywords) {
        for (String kw : keywords) {
            if (input.contains(kw)) return kw;
        }
        return null;
    }

    private TriageResponse buildKeywordTriage(
            String ip, String user, String host,
            String ruleName, String severity,
            String mitre, String matchedKeyword) {

        Alert alert = new Alert();
        alert.id               = "EVT-" + System.currentTimeMillis();
        alert.ruleName         = ruleName;
        alert.severity         = severity;
        alert.srcIp            = ip;
        alert.user             = user;
        alert.host             = host;
        alert.category         = "intrusion";
        alert.assetCriticality = "CRITICAL";
        alert.source           = "LoginKeywordDetector";
        alert.timestamp        = System.currentTimeMillis();

        int    score      = AlertScorer.score(alert);
        String incidentId = "INC-" + System.currentTimeMillis();

        String explanation = String.format(
                "Login field contained attack keyword '%s' from IP %s targeting user '%s'. "
                + "Rule: %s. Asset criticality: CRITICAL. "
                + "This pattern matches %s.",
                matchedKeyword, ip, user, ruleName, mitre);

        String recommendation = switch (severity) {
            case "CRITICAL" -> String.format(
                    "Immediately block source IP %s at the perimeter firewall. "
                    + "Isolate host %s. Inspect running processes for C2 beacons or "
                    + "dropped payloads. Escalate to Tier 2.", ip, host);
            default -> String.format(
                    "Block source IP %s. Review database query logs on %s for "
                    + "successful injection. Check WAF rules for SQLi coverage.", ip, host);
        };

        return new TriageResponse(incidentId, severity, score,
                explanation, recommendation, mitre, alert);
    }

    private String resolveClientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
