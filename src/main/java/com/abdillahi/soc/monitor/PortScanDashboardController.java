package com.abdillahi.soc.monitor;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class PortScanDashboardController {

    private final PortScanIncidentStore incidentStore;

    public PortScanDashboardController(PortScanIncidentStore incidentStore) {
        this.incidentStore = incidentStore;
    }

    @GetMapping("/port-scan-dashboard")
    public String dashboard(Model model) {
        model.addAttribute("incident", incidentStore.getLatest());
        return "port-scan-dashboard";
    }
}
