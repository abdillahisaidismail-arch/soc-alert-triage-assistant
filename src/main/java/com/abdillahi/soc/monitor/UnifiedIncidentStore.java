package com.abdillahi.soc.monitor;

import org.springframework.stereotype.Component;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

@Component
public class UnifiedIncidentStore {

    private static final int MAX_INCIDENTS = 50;
    private final Deque<DashboardIncident> incidents = new ArrayDeque<>();

    public synchronized void add(DashboardIncident incident) {
        incidents.addFirst(incident);
        while (incidents.size() > MAX_INCIDENTS) {
            incidents.removeLast();
        }
    }

    public synchronized List<DashboardIncident> all() {
        return new ArrayList<>(incidents);
    }

    public synchronized DashboardIncident latest() {
        return incidents.peekFirst();
    }
}
