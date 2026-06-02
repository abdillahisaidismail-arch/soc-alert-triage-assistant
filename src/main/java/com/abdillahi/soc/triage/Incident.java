package com.abdillahi.soc.triage;

import com.abdillahi.soc.model.Alert;

import java.util.ArrayList;
import java.util.List;

public class Incident {
    public String key;          // grouping key: user+ip
    public List<Alert> alerts = new ArrayList<>();
    public int totalScore;

    public Incident(String key) {
        this.key = key;
    }

    public void add(Alert a, int score) {
        alerts.add(a);
        totalScore += score;
    }

    public String summary() {
        if (alerts.isEmpty()) return "Empty incident";
        Alert first = alerts.get(0);
        return "Incident[" + key + "] totalScore=" + totalScore +
                " alerts=" + alerts.size() +
                " firstRule=" + first.ruleName +
                " host=" + first.host +
                " user=" + first.user +
                " srcIp=" + first.srcIp;
    }
}