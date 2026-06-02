package com.abdillahi.soc.monitor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.Set;

@Component
public class RemediationInterceptor implements HandlerInterceptor {

    private static final Set<String> WHITELIST = Set.of(
            "/soc-dashboard",
            "/api/actions/unblock-ip",
            "/api/actions/unlock-account",
            "/api/actions/dismiss"
    );

    private final RemediationStore store;

    public RemediationInterceptor(RemediationStore store) {
        this.store = store;
    }

    @Override
    public boolean preHandle(
            HttpServletRequest request,
            HttpServletResponse response,
            Object handler
    ) throws Exception {

        String path = request.getRequestURI();

        if (WHITELIST.contains(path)) {
            return true;
        }

        String ip = resolveIp(request);

        if (store.isBlocked(ip)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("text/html;charset=UTF-8");
            response.getWriter().write(blockedPage(ip));
            return false;
        }

        return true;
    }

    private String resolveIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private String blockedPage(String ip) {
        return """
                <!DOCTYPE html>
                <html lang="en">
                <head>
                  <meta charset="UTF-8">
                  <title>403 — Blocked by SOC</title>
                  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
                  <style>
                    body { margin:0; font-family:'JetBrains Mono',monospace; background:#0d1117; color:#e6edf3;
                           display:flex; align-items:center; justify-content:center; min-height:100vh;
                           flex-direction:column; gap:18px; text-align:center; padding:24px; }
                    .code { font-size:72px; font-weight:700; color:#ff4d4f; }
                    .msg  { font-size:16px; color:#8b949e; max-width:48ch; line-height:1.7; }
                    .ip   { font-size:14px; color:#ff4d4f; background:#3d1010; padding:4px 12px; border-radius:6px; }
                    a     { color:#58a6ff; font-size:13px; text-decoration:none; border:1px solid #30363d;
                            padding:8px 16px; border-radius:8px; }
                    a:hover { background:#161b22; }
                  </style>
                </head>
                <body>
                  <div class="code">403</div>
                  <div class="ip">%s</div>
                  <div class="msg">Your IP has been blocked by the SOC Triage System following a detected attack.</div>
                  <a href="/soc-dashboard">&#x2192; Go to SOC Dashboard to unblock</a>
                </body>
                </html>
                """.formatted(ip);
    }
}
