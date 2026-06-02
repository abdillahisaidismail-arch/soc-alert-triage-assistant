package com.abdillahi.soc.model;

/**
 * Lightweight record of a single failed login attempt.
 * Stored in-memory by AttackMonitorService.
 */
public class LoginAttempt {

    public final String sourceIp;
    public final String username;
    public final String targetHost;
    public final long   timestampMs;

    public LoginAttempt(String sourceIp, String username, String targetHost) {
        this.sourceIp    = sourceIp;
        this.username    = username;
        this.targetHost  = targetHost;
        this.timestampMs = System.currentTimeMillis();
    }
}
