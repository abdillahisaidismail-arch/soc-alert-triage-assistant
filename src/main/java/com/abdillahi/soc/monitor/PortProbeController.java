package com.abdillahi.soc.monitor;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/probes")
public class PortProbeController {

    private final PortScanDetectorService detectorService;
    private final PortScanEmailService emailService;

    public PortProbeController(PortScanDetectorService detectorService, PortScanEmailService emailService) {
        this.detectorService = detectorService;
        this.emailService = emailService;
    }

    @GetMapping("/{port}")
    public ResponseEntity<Map<String, Object>> recordProbe(
            @PathVariable int port,
            HttpServletRequest request,
            @RequestHeader(value = "User-Agent", required = false) String userAgent
    ) {
        if (port < 1 || port > 65535) {
            return ResponseEntity.badRequest().body(Map.of(
                    "status", "invalid_port",
                    "message", "Port must be between 1 and 65535"
            ));
        }

        String sourceIp = resolveClientIp(request);
        PortScanIncidentResponse incident = detectorService.recordProbe(sourceIp, port, userAgent);

        if (incident != null) {
            emailService.send(incident);
            return ResponseEntity.ok(Map.of(
                    "status", "incident_created",
                    "sourceIp", sourceIp,
                    "port", port,
                    "incident", incident
            ));
        }

        return ResponseEntity.ok(Map.of(
                "status", "probe_recorded",
                "sourceIp", sourceIp,
                "port", port
        ));
    }

    private String resolveClientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
