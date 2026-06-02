package com.abdillahi.soc.triage;

import com.abdillahi.soc.model.Alert;

public class AlertScorer {

    public static int score(Alert a) {
        int score = 0;

        // 1) Base score from severity
        switch (safe(a.severity)) {
            case "CRITICAL" -> score += 70;
            case "HIGH"     -> score += 50;
            case "MEDIUM"   -> score += 30;
            case "LOW"      -> score += 10;
        }

        // 2) Boost from asset criticality
        switch (safe(a.assetCriticality)) {
            case "HIGH"   -> score += 20;
            case "MEDIUM" -> score += 10;
            case "LOW"    -> score += 0;
        }

        // 3) Extra boost for specific rule types
        String rule = safe(a.ruleName);
        if (rule.contains("MALWARE"))     score += 20;
        if (rule.contains("ADMIN LOGIN")) score += 10;
        if (rule.contains("PORT SCAN"))   score += 5;

        return score;
    }

    public static String bucket(int score) {
        if (score >= 70) return "CRITICAL";
        if (score >= 50) return "HIGH";
        if (score >= 30) return "MEDIUM";
        return "LOW";
    }

    private static String safe(String s) {
        return s == null ? "" : s.toUpperCase();
    }
}