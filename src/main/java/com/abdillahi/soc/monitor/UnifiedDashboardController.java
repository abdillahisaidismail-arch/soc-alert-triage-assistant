package com.abdillahi.soc.monitor;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.List;

@Controller
public class UnifiedDashboardController {

    private final UnifiedIncidentStore incidentStore;

    public UnifiedDashboardController(UnifiedIncidentStore incidentStore) {
        this.incidentStore = incidentStore;
    }

    @GetMapping("/soc-dashboard")
    public String dashboard(Model model) {
        List<DashboardIncident> incidents = incidentStore.all();

        long criticalCount = incidents.stream()
                .filter(i -> "CRITICAL".equalsIgnoreCase(i.severity()))
                .count();

        long highCount = incidents.stream()
                .filter(i -> "HIGH".equalsIgnoreCase(i.severity()))
                .count();

        model.addAttribute("incidents", incidents);
        model.addAttribute("latest", incidentStore.latest());
        model.addAttribute("totalCount", incidents.size());
        model.addAttribute("criticalCount", criticalCount);
        model.addAttribute("highCount", highCount);

        return "soc-dashboard";
    }
}
