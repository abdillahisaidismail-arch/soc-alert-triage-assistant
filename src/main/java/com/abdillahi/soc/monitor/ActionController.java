package com.abdillahi.soc.monitor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Handles analyst response actions triggered from the email alert buttons:
 *   GET /api/actions/block-ip
 *   GET /api/actions/lock-account
 *   GET /api/actions/dismiss
 *
 * In production these would call a SOAR/firewall API.
 * Here they log the action and render a confirmation page.
 */
@Controller
@RequestMapping("/api/actions")
public class ActionController {

    private static final Logger log = LoggerFactory.getLogger(ActionController.class);

    private final AttackMonitorService monitor;

    public ActionController(AttackMonitorService monitor) {
        this.monitor = monitor;
    }

    @GetMapping("/block-ip")
    public String blockIp(
            @RequestParam String ip,
            @RequestParam(defaultValue = "unknown") String incident,
            Model model) {
        log.warn("[ACTION] BLOCK IP {} — incident {}", ip, incident);
        monitor.clearIp(ip);
        model.addAttribute("action",   "Block IP");
        model.addAttribute("target",   ip);
        model.addAttribute("incident", incident);
        model.addAttribute("message",
                "IP " + ip + " has been flagged for blocking. In a live environment this "
                + "would push a deny rule to the perimeter firewall via your SOAR integration.");
        return "action-result";
    }

    @GetMapping("/lock-account")
    public String lockAccount(
            @RequestParam String user,
            @RequestParam(defaultValue = "unknown") String incident,
            Model model) {
        log.warn("[ACTION] LOCK ACCOUNT '{}' — incident {}", user, incident);
        model.addAttribute("action",   "Lock Account");
        model.addAttribute("target",   user);
        model.addAttribute("incident", incident);
        model.addAttribute("message",
                "Account '" + user + "' has been flagged for lockout. In a live environment this "
                + "would call your identity provider (AD / Okta / Keycloak) to disable the account.");
        return "action-result";
    }

    @GetMapping("/dismiss")
    public String dismiss(
            @RequestParam(defaultValue = "unknown") String incident,
            Model model) {
        log.info("[ACTION] DISMISS incident {}", incident);
        model.addAttribute("action",   "Dismiss");
        model.addAttribute("target",   "—");
        model.addAttribute("incident", incident);
        model.addAttribute("message",
                "Incident " + incident + " has been dismissed and added to the suppression list.");
        return "action-result";
    }
}
