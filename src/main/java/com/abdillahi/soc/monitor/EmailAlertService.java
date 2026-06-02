package com.abdillahi.soc.monitor;

import com.abdillahi.soc.triage.TriageResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import jakarta.mail.internet.MimeMessage;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/**
 * Sends a formatted HTML incident report via Mailtrap SMTP
 * whenever the brute-force threshold is crossed.
 */
@Service
public class EmailAlertService {

    private static final Logger log = LoggerFactory.getLogger(EmailAlertService.class);
    private static final DateTimeFormatter FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z")
                             .withZone(ZoneId.systemDefault());

    private final JavaMailSender mailSender;

    @Value("${alert.recipient}")
    private String recipient;

    @Value("${alert.sender}")
    private String sender;

    public EmailAlertService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    public void sendIncidentAlert(TriageResponse triage) {
        try {
            MimeMessage msg = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(msg, true, "UTF-8");

            helper.setFrom(sender);
            helper.setTo(recipient);
            helper.setSubject(String.format("[SOC ALERT] %s — %s | Score %d",
                    triage.severity, triage.incidentId, triage.riskScore));
            helper.setText(buildHtmlBody(triage), true);

            mailSender.send(msg);
            log.info("[EMAIL] Incident alert sent for {} to {}", triage.incidentId, recipient);

        } catch (Exception e) {
            log.error("[EMAIL] Failed to send alert for {}: {}", triage.incidentId, e.getMessage());
        }
    }

    // -------------------------------------------------------------------------

    private String buildHtmlBody(TriageResponse t) {
        String sevColor = switch (t.severity) {
            case "CRITICAL" -> "#ff4d4f";
            case "HIGH"     -> "#fa8c16";
            case "MEDIUM"   -> "#fadb14";
            default         -> "#52c41a";
        };

        String src = t.sourceAlert != null ? t.sourceAlert.srcIp : "unknown";
        String usr = t.sourceAlert != null ? t.sourceAlert.user  : "unknown";
        String hst = t.sourceAlert != null ? t.sourceAlert.host  : "unknown";
        String ts  = FMT.format(Instant.now());

        return "<!DOCTYPE html>" +
            "<html><head><meta charset='UTF-8'></head>" +
            "<body style='margin:0;padding:0;background:#0d1117;font-family:monospace;'>" +
            "<table width='100%' cellpadding='0' cellspacing='0' style='background:#0d1117;padding:32px 0;'>" +
            "<tr><td align='center'>" +
            "<table width='600' cellpadding='0' cellspacing='0' style='background:#161b22;border:1px solid #30363d;border-radius:12px;overflow:hidden;'>" +

            // Header
            "<tr><td style='background:#161b22;padding:24px 32px;border-bottom:1px solid #30363d;'>" +
            "<table width='100%'><tr>" +
            "<td><span style='font-size:18px;font-weight:700;color:#e6edf3;'>&#x1F6E1; SOC Alert Triage Assistant</span><br>" +
            "<span style='font-size:12px;color:#8b949e;'>Automated Incident Report</span></td>" +
            "<td align='right'><span style='background:" + sevColor + "22;color:" + sevColor + ";" +
            "padding:4px 14px;border-radius:9999px;font-size:13px;font-weight:700;letter-spacing:0.5px;'>" +
            t.severity + "</span></td>" +
            "</tr></table></td></tr>" +

            // Score + Incident ID
            "<tr><td style='padding:20px 32px;border-bottom:1px solid #30363d;'>" +
            "<table width='100%'><tr>" +
            "<td><span style='font-size:42px;font-weight:700;color:" + sevColor + ";'>" + t.riskScore + "</span>" +
            "<span style='font-size:12px;color:#8b949e;margin-left:8px;'>/ 100 risk score</span></td>" +
            "<td align='right' style='color:#8b949e;font-size:12px;'>" + t.incidentId + "<br>" + ts + "</td>" +
            "</tr></table></td></tr>" +

            // Alert details table
            "<tr><td style='padding:20px 32px;border-bottom:1px solid #30363d;'>" +
            "<table width='100%' style='border-collapse:collapse;'>" +
            row("Source IP",       src) +
            row("Target User",     usr) +
            row("Target Host",     hst) +
            row("MITRE Technique", t.mitreTechnique) +
            "</table></td></tr>" +

            // Explanation
            "<tr><td style='padding:20px 32px;border-bottom:1px solid #30363d;'>" +
            "<p style='font-size:11px;color:#484f58;text-transform:uppercase;letter-spacing:0.8px;margin:0 0 8px;'>WHY THIS SEVERITY</p>" +
            "<p style='font-size:13px;color:#e6edf3;line-height:1.65;margin:0;'>" + t.explanation + "</p></td></tr>" +

            // Recommendation
            "<tr><td style='padding:20px 32px;border-bottom:1px solid #30363d;'>" +
            "<p style='font-size:11px;color:#484f58;text-transform:uppercase;letter-spacing:0.8px;margin:0 0 8px;'>ANALYST RECOMMENDATION</p>" +
            "<div style='background:#1f3a5f;border-left:3px solid #58a6ff;padding:12px 16px;border-radius:0 6px 6px 0;" +
            "font-size:13px;color:#e6edf3;line-height:1.65;'>" + t.recommendation + "</div></td></tr>" +

            // Action buttons
            "<tr><td style='padding:20px 32px;'>" +
            "<p style='font-size:11px;color:#484f58;text-transform:uppercase;letter-spacing:0.8px;margin:0 0 12px;'>ANALYST ACTIONS</p>" +
            "<table><tr>" +
            "<td style='padding-right:8px;'>" +
            "<a href='http://localhost:8081/api/actions/block-ip?ip=" + src + "&incident=" + t.incidentId + "'" +
            " style='background:#ff4d4f;color:#fff;padding:8px 18px;border-radius:6px;text-decoration:none;font-size:13px;font-weight:700;'>&#x26D4; Block IP</a></td>" +
            "<td style='padding-right:8px;'>" +
            "<a href='http://localhost:8081/api/actions/lock-account?user=" + usr + "&incident=" + t.incidentId + "'" +
            " style='background:#fa8c16;color:#0d1117;padding:8px 18px;border-radius:6px;text-decoration:none;font-size:13px;font-weight:700;'>&#x1F512; Lock Account</a></td>" +
            "<td>" +
            "<a href='http://localhost:8081/api/actions/dismiss?incident=" + t.incidentId + "'" +
            " style='background:#30363d;color:#e6edf3;padding:8px 18px;border-radius:6px;text-decoration:none;font-size:13px;font-weight:700;'>Dismiss</a></td>" +
            "</tr></table></td></tr>" +

            "</table></td></tr></table>" +
            "</body></html>";
    }

    private String row(String label, String value) {
        return "<tr>" +
            "<td style='padding:6px 0;font-size:11px;color:#484f58;text-transform:uppercase;letter-spacing:0.6px;width:140px;'>" + label + "</td>" +
            "<td style='padding:6px 0;font-size:13px;color:#e6edf3;font-weight:500;'>" + (value != null ? value : "—") + "</td>" +
            "</tr>";
    }
}
