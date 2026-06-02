package com.abdillahi.soc.model;

public class Alert {
    public String id;
    public String source;
    public String ruleName;
    public String severity;          // LOW, MEDIUM, HIGH, CRITICAL
    public String host;
    public String user;
    public String srcIp;
    public String category;          // auth, malware, network...
    public String assetCriticality;  // LOW, MEDIUM, HIGH
    public long timestamp;

    @Override
    public String toString() {
        return "[" + severity + "] " + ruleName +
               " | host=" + host +
               " | user=" + user +
               " | ip=" + srcIp +
               " | asset=" + assetCriticality;
    }
}