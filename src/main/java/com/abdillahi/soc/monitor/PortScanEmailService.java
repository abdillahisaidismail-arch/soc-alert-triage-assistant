package com.abdillahi.soc.monitor;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class PortScanEmailService {

    private final JavaMailSender mailSender;

    @Value("${soc.alert.mail.to:abdillahipro@gmail.com}")
    private String recipient;

    public PortScanEmailService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    public void send(PortScanIncidentResponse incident) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(recipient);
        message.setSubject("[SOC] Port Scan Detected - " + incident.sourceIp());
        message.setText(buildBody(incident));
        mailSender.send(message);
    }

    private String buildBody(PortScanIncidentResponse incident) {
        return """
                SOC ALERT TRIAGE ASSISTANT

                Incident ID: %s
                Severity: %s
                Risk Score: %d
                MITRE: %s

                Source IP: %s
                Origin: %s, %s
                ISP: %s

                Ports Scanned: %s
                Total Probes: %d
                Duration: %d seconds

                Explanation:
                %s

                Recommendation:
                %s
                """.formatted(
                incident.incidentId(),
                incident.severity(),
                incident.riskScore(),
                incident.mitreTechnique(),
                incident.sourceIp(),
                incident.city(),
                incident.country(),
                incident.isp(),
                incident.portsScanned(),
                incident.totalProbes(),
                incident.durationSeconds(),
                incident.explanation(),
                incident.recommendation()
        );
    }
}
