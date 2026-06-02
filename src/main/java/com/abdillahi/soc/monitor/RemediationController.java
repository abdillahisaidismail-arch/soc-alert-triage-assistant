package com.abdillahi.soc.monitor;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequestMapping("/api/actions")
public class RemediationController {

    private final RemediationStore store;

    public RemediationController(RemediationStore store) {
        this.store = store;
    }

    @GetMapping("/block-ip")
    public String blockIp(
            @RequestParam String ip,
            @RequestParam(required = false) String incident,
            RedirectAttributes redirectAttrs
    ) {
        store.blockIp(ip, incident != null ? incident : "manual");
        redirectAttrs.addFlashAttribute("remediationMessage",
                "IP " + ip + " has been blocked. All requests from this source will receive 403 Forbidden.");
        return "redirect:/soc-dashboard";
    }

    @GetMapping("/lock-account")
    public String lockAccount(
            @RequestParam String user,
            @RequestParam(required = false) String incident,
            RedirectAttributes redirectAttrs
    ) {
        store.lockAccount(user, incident != null ? incident : "manual");
        redirectAttrs.addFlashAttribute("remediationMessage",
                "Account '" + user + "' has been locked. Login attempts will be rejected.");
        return "redirect:/soc-dashboard";
    }

    @GetMapping("/unblock-ip")
    public String unblockIp(
            @RequestParam String ip,
            RedirectAttributes redirectAttrs
    ) {
        store.unblockIp(ip);
        redirectAttrs.addFlashAttribute("remediationMessage",
                "IP " + ip + " has been unblocked.");
        return "redirect:/soc-dashboard";
    }

    @GetMapping("/unlock-account")
    public String unlockAccount(
            @RequestParam String user,
            RedirectAttributes redirectAttrs
    ) {
        store.unlockAccount(user);
        redirectAttrs.addFlashAttribute("remediationMessage",
                "Account '" + user + "' has been unlocked.");
        return "redirect:/soc-dashboard";
    }

    @GetMapping("/dismiss")
    public String dismiss(
            @RequestParam(required = false) String incident,
            RedirectAttributes redirectAttrs
    ) {
        redirectAttrs.addFlashAttribute("remediationMessage",
                "Incident " + incident + " dismissed. No action taken.");
        return "redirect:/soc-dashboard";
    }
}
