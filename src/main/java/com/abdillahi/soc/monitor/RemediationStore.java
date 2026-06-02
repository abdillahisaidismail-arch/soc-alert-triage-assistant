package com.abdillahi.soc.monitor;

import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class RemediationStore {

    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public record BlockedIp(String ip, String incidentId, String blockedAt) {}
    public record LockedAccount(String username, String incidentId, String lockedAt) {}

    private final Map<String, BlockedIp>     blockedIps      = new ConcurrentHashMap<>();
    private final Map<String, LockedAccount> lockedAccounts  = new ConcurrentHashMap<>();

    public void blockIp(String ip, String incidentId) {
        blockedIps.put(ip, new BlockedIp(ip, incidentId, LocalDateTime.now().format(TS)));
    }

    public void lockAccount(String username, String incidentId) {
        lockedAccounts.put(username, new LockedAccount(username, incidentId, LocalDateTime.now().format(TS)));
    }

    public void unblockIp(String ip) {
        blockedIps.remove(ip);
    }

    public void unlockAccount(String username) {
        lockedAccounts.remove(username);
    }

    public boolean isBlocked(String ip) {
        return ip != null && blockedIps.containsKey(ip);
    }

    public boolean isLocked(String username) {
        return username != null && lockedAccounts.containsKey(username);
    }

    public List<BlockedIp> allBlockedIps() {
        return new ArrayList<>(blockedIps.values());
    }

    public List<LockedAccount> allLockedAccounts() {
        return new ArrayList<>(lockedAccounts.values());
    }
}
