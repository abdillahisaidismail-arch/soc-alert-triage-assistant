package com.abdillahi.soc.triage;

import com.abdillahi.soc.model.Alert;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class IncidentGrouper {

    // Simple grouping: same user + same srcIp
    public static List<Incident> groupByUserAndIp(List<Alert> alerts) {
        Map<String, Incident> map = new HashMap<>();

        for (Alert a : alerts) {
            int score = AlertScorer.score(a);
            String user = a.user == null ? "" : a.user;
            String ip   = a.srcIp == null ? "" : a.srcIp;
            String key  = user + "@" + ip;

            Incident incident = map.computeIfAbsent(key, Incident::new);
            incident.add(a, score);
        }

        List<Incident> list = new ArrayList<>(map.values());
        // sort incidents by totalScore descending
        list.sort(Comparator.comparingInt(i -> -i.totalScore));
        return list;
    }
}