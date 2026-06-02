package com.abdillahi.soc.monitor;

import com.abdillahi.soc.triage.TriageResponse;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Serves the demo login page and processes login attempts.
 *
 * GET  /login  — renders the login form (login.html)
 * POST /login  — validates credentials; on failure, records the attempt
 *               in AttackMonitorService. When the brute-force threshold is
 *               crossed, sends an email alert via Mailtrap and shows an
 *               incident card directly on the login page.
 *
 * Demo credentials:  username=admin  password=secret123
 */
@Controller
public class LoginController {

    private static final String VALID_USER = "admin";
    private static final String VALID_PASS = "secret123";

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

        if (VALID_USER.equals(username) && VALID_PASS.equals(password)) {
            model.addAttribute("success", true);
            return "login";
        }

        String sourceIp = resolveClientIp(request);
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

    private String resolveClientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
