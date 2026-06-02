package com.abdillahi.soc.monitor;

import org.springframework.stereotype.Component;

import java.util.concurrent.atomic.AtomicReference;

@Component
public class PortScanIncidentStore {

    private final AtomicReference<PortScanIncidentResponse> latest = new AtomicReference<>();

    public void save(PortScanIncidentResponse incident) {
        latest.set(incident);
    }

    public PortScanIncidentResponse getLatest() {
        return latest.get();
    }
}
