package com.abdillahi.soc.triage;

import com.abdillahi.soc.model.Alert;

/**
 * DTO returned by POST /api/alerts/triage.
 *
 * Fields are intentionally public (no-boilerplate style consistent
 * with the existing Alert.java in this project) and Jackson-serialisable.
 */
public class TriageResponse {

    /** Auto-generated or derived incident identifier. */
    public String incidentId;

    /** Bucketed severity: CRITICAL | HIGH | MEDIUM | LOW */
    public String severity;

    /** Numeric risk score produced by AlertScorer. */
    public int riskScore;

    /** Human-readable explanation of why this severity was assigned. */
    public String explanation;

    /** Recommended analyst action based on rule type and severity. */
    public String recommendation;

    /** MITRE ATT&CK technique ID and name inferred from the alert. */
    public String mitreTechnique;

    /** The original alert that was triaged, echoed back for traceability. */
    public Alert sourceAlert;

    public TriageResponse(
            String incidentId,
            String severity,
            int riskScore,
            String explanation,
            String recommendation,
            String mitreTechnique,
            Alert sourceAlert) {
        this.incidentId     = incidentId;
        this.severity       = severity;
        this.riskScore      = riskScore;
        this.explanation    = explanation;
        this.recommendation = recommendation;
        this.mitreTechnique = mitreTechnique;
        this.sourceAlert    = sourceAlert;
    }
}
