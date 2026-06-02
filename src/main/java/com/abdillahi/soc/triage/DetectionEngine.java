package com.abdillahi.soc.triage;

import com.abdillahi.soc.model.Alert;

import java.util.List;

public class DetectionEngine {

    public static void analyze(List<Incident> incidents) {
        System.out.println("\n=== Detection Engine ===\n");

        for (Incident inc : incidents) {
            detectAccountCompromise(inc);
            detectMalwareOnHighAsset(inc);
            detectLonePortScan(inc);
        }
    }

    // Rule 1: >= 2 failed logins + 1 successful login from same user@ip
    private static void detectAccountCompromise(Incident inc) {
        long failedLogins = inc.alerts.stream()
                .filter(a -> a.ruleName != null &&
                             a.ruleName.toLowerCase().contains("failed login"))
                .count();

        long successLogins = inc.alerts.stream()
                .filter(a -> a.ruleName != null &&
                             a.ruleName.toLowerCase().contains("successful"))
                .count();

        if (failedLogins >= 2 && successLogins >= 1) {
            System.out.println("🚨 FLAGGED [POSSIBLE ACCOUNT COMPROMISE]");
            System.out.println("   User/IP  : " + inc.key);
            System.out.println("   Failed logins  : " + failedLogins);
            System.out.println("   Successful logins: " + successLogins);
            System.out.println("   Alerts involved  : " + inc.alerts.size());
            System.out.println("   Total score      : " + inc.totalScore);
            System.out.println("   Recommendation   : Investigate alice's account.");
            System.out.println("                      Check if the login IP is known.");
            System.out.println("                      Consider locking the account.");
            System.out.println();
        }
    }

    // Rule 2: Malware on a HIGH-criticality asset
    private static void detectMalwareOnHighAsset(Incident inc) {
        boolean hasMalware = inc.alerts.stream()
                .anyMatch(a -> a.ruleName != null &&
                               a.ruleName.toLowerCase().contains("malware") &&
                               "HIGH".equalsIgnoreCase(a.assetCriticality));

        if (hasMalware) {
            Alert a = inc.alerts.stream()
                    .filter(x -> x.ruleName != null &&
                                 x.ruleName.toLowerCase().contains("malware"))
                    .findFirst().orElse(null);

            System.out.println("🚨 FLAGGED [MALWARE ON HIGH-CRITICALITY ASSET]");
            System.out.println("   User/IP  : " + inc.key);
            if (a != null) {
                System.out.println("   Host     : " + a.host);
                System.out.println("   Rule     : " + a.ruleName);
            }
            System.out.println("   Total score      : " + inc.totalScore);
            System.out.println("   Recommendation   : Isolate " +
                    (a != null ? a.host : "host") + " immediately.");
            System.out.println("                      Run full forensic scan.");
            System.out.println("                      Check for lateral movement.");
            System.out.println();
        }
    }

    // Rule 3: Lone port scan (no other alerts from same IP) — low priority
    private static void detectLonePortScan(Incident inc) {
        boolean hasPortScan = inc.alerts.stream()
                .anyMatch(a -> a.ruleName != null &&
                               a.ruleName.toLowerCase().contains("port scan"));

        if (hasPortScan && inc.alerts.size() == 1) {
            System.out.println("ℹ️  INFO [PORT SCAN - MONITOR ONLY]");
            System.out.println("   Source IP : " + inc.key);
            System.out.println("   Score     : " + inc.totalScore);
            System.out.println("   Recommendation: Add IP to watchlist.");
            System.out.println("                   No immediate action required.");
            System.out.println();
        }
    }
}