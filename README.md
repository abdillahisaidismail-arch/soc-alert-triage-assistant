<div align="center">

# 🛡️ SOC Alert Triage Assistant

**A real-time Security Operations Center (SOC) platform built with Java 21 & Spring Boot 3.2.5**

![Java](https://img.shields.io/badge/Java-21-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white)
![Spring Boot](https://img.shields.io/badge/Spring_Boot-3.2.5-6DB33F?style=for-the-badge&logo=spring-boot&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-5_Techniques-red?style=for-the-badge)
![Maven](https://img.shields.io/badge/Maven-Build-C71A36?style=for-the-badge&logo=apache-maven&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)

*Portfolio project — L3 → Master's Cybersecurity | ISTIC Université de Rennes*

</div>

---

## 📌 Overview

The **SOC Alert Triage Assistant** is a full-stack cybersecurity platform that simulates a real Security Operations Center environment. It detects attacks in real time against a local target web application, automatically triages them using a risk scoring engine, maps them to MITRE ATT&CK techniques, sends formatted email alerts, and lets analysts take one-click remediation actions directly from a unified dashboard.

Built to demonstrate practical SOC analyst skills for an alternance in cybersecurity — including threat detection, alert triage, MITRE mapping, GeoIP enrichment, and automated incident response.

---

## ✨ Features

- **Real-time attack detection** — Brute Force, SQL Injection, Malware/Command Injection, Credential Stuffing, Port Scanning
- **Automated risk scoring** — numeric 0–100 score with severity bucketing (CRITICAL / HIGH / MEDIUM / LOW)
- **MITRE ATT&CK mapping** — 5 techniques mapped and displayed on every incident
- **GeoIP enrichment** — every incident enriched with attacker country, city, and ISP
- **Email alerts** — formatted HTML incident reports sent via SMTP (Mailtrap / Gmail)
- **Auto-remediation** — one-click IP block (returns 403 Forbidden) and account lockout enforced at the interceptor level
- **Unified SOC dashboard** — live incident timeline, severity counters, active remediations panel
- **REST triage API** — `POST /api/alerts/triage` accepts any alert JSON and returns a full incident response

---

## 🗺️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Browser / Attacker                        │
└────────────┬──────────────────┬──────────────────┬──────────────┘
             │                  │                  │
      POST /login        GET /api/probes/{port}  POST /api/alerts/triage
             │                  │                  │
┌────────────▼──────────────────▼──────────────────▼──────────────┐
│                    RemediationInterceptor                         │
│              (blocks IP before any controller runs)              │
└────────────┬──────────────────┬──────────────────┬──────────────┘
             │                  │                  │
   ┌─────────▼──────┐  ┌────────▼────────┐  ┌─────▼──────────────┐
   │ LoginController│  │PortProbeCtrl    │  │  AlertController   │
   └─────────┬──────┘  └────────┬────────┘  └─────┬──────────────┘
             │                  │                  │
   ┌─────────▼──────────────────▼──────────────────▼──────────────┐
   │                     Detection Engine                          │
   │  AttackMonitorService · PortScanDetectorService · AlertScorer │
   └─────────┬─────────────────────────────────────────────────────┘
             │
   ┌─────────▼─────────────────────────────────────────────────────┐
   │                    Enrichment & Alerting                       │
   │         GeoIpService · EmailAlertService · PortScanEmailSvc   │
   └─────────┬─────────────────────────────────────────────────────┘
             │
   ┌─────────▼─────────────────────────────────────────────────────┐
   │                     Incident Stores                            │
   │         UnifiedIncidentStore · PortScanIncidentStore           │
   └─────────┬─────────────────────────────────────────────────────┘
             │
   ┌─────────▼─────────────────────────────────────────────────────┐
   │                      SOC Dashboard                             │
   │   /soc-dashboard — incidents · remediations · stats            │
   └───────────────────────────────────────────────────────────────┘
```

---

## 🎯 MITRE ATT&CK Coverage

| Technique ID | Name | Trigger | Severity |
|---|---|---|---|
| T1110 | Brute Force | 5 failed logins from same IP in 60s | HIGH |
| T1110.004 | Credential Stuffing | Wordlist rotation pattern detected | HIGH |
| T1059 | Command and Scripting Interpreter | `powershell`, `mimikatz`, `eval(`, `/bin/`… in login field | CRITICAL |
| T1190 | Exploit Public-Facing Application | `' or`, `1=1--`, `union select`… in login field | HIGH |
| T1046 | Network Service Scanning | 10+ port probes from same IP in 30s | MEDIUM |

---

## 🏗️ Project Structure

```
src/main/java/com/abdillahi/soc/
├── App.java                              ← @SpringBootApplication entry point
├── HomeController.java                   ← GET / → manual triage lab
├── io/AlertLoader.java                   ← loads alerts from alerts.json
├── model/Alert.java                      ← alert fields: srcIp, user, ruleName…
├── triage/
│   ├── AlertController.java              ← POST /api/alerts/triage (REST endpoint)
│   ├── AlertScorer.java                  ← computes numeric risk score (0–100)
│   ├── DetectionEngine.java              ← orchestrates scoring + grouping
│   ├── Incident.java                     ← result object
│   ├── IncidentGrouper.java              ← groups related alerts into incidents
│   └── TriageResponse.java               ← REST response DTO
└── monitor/
    ├── LoginController.java              ← POST /login — attack detection
    ├── AttackMonitorService.java         ← brute force threshold tracking
    ├── EmailAlertService.java            ← SMTP email alerts (Mailtrap)
    ├── GeoIpService.java                 ← GeoIP enrichment (ip-api.com)
    ├── GeoIpInfo.java                    ← GeoIP record
    ├── PortProbeController.java          ← GET /api/probes/{port}
    ├── PortScanDetectorService.java      ← port scan threshold tracking
    ├── PortScanEmailService.java         ← port scan email alerts
    ├── PortScanIncidentResponse.java     ← port scan incident DTO
    ├── PortScanIncidentStore.java        ← port scan in-memory store
    ├── PortScanDashboardController.java  ← GET /port-scan-dashboard
    ├── DashboardIncident.java            ← unified incident record
    ├── UnifiedIncidentStore.java         ← in-memory incident timeline (max 50)
    ├── UnifiedDashboardController.java   ← GET /soc-dashboard
    ├── RemediationStore.java             ← blocked IPs + locked accounts
    ├── RemediationController.java        ← GET /api/actions/*
    ├── RemediationInterceptor.java       ← 403 enforcer for blocked IPs
    └── WebConfig.java                    ← registers interceptor with Spring MVC

src/main/resources/
├── alerts.json                           ← sample alert data
├── application.properties                ← server.port=8081, SMTP config
└── templates/
    ├── home.html                         ← manual triage lab dashboard
    ├── login.html                        ← target login form
    ├── soc-dashboard.html                ← unified analyst dashboard
    └── port-scan-dashboard.html          ← port scan detail view
```

---

## 🚀 Getting Started

### Prerequisites

- Java 21+
- Maven 3.9+
- A free [Mailtrap](https://mailtrap.io) account (for email alerts)

### 1 — Clone the repo

```bash
git clone https://github.com/abdillahisaidismail-arch/soc-alert-triage-assistant.git
cd soc-alert-triage-assistant
```

### 2 — Configure email (optional)

Edit `src/main/resources/application.properties`:

```properties
spring.mail.host=sandbox.smtp.mailtrap.io
spring.mail.port=2525
spring.mail.username=YOUR_MAILTRAP_USERNAME
spring.mail.password=YOUR_MAILTRAP_PASSWORD
```

### 3 — Run

```bash
mvn spring-boot:run
```

App starts on `http://localhost:8081`.

---

## 🧪 Simulating Attacks

### Malware / Command Injection (T1059)

Go to `http://localhost:8081/login` and enter:
- **Username:** `powershell`
- **Password:** `anything`

Expected: CRITICAL incident card with MITRE T1059.

### SQL Injection (T1190)

- **Username:** `admin' or 1=1--`
- **Password:** `anything`

Expected: HIGH incident card with MITRE T1190.

### Brute Force (T1110)

Submit wrong credentials 5 times with the same username:
- **Username:** `admin`
- **Password:** `wrong1` through `wrong5`

Expected: HIGH incident after the 5th attempt.

### Port Scan (T1046)

```bash
python3 scripts/scan_attack.py
```

Expected: MEDIUM incident in the dashboard with ports grid.

---

## 🛡️ Auto-Remediation

From the SOC dashboard or the login incident card, analysts can take immediate action:

| Action | Effect |
|---|---|
| **⛔ Block IP** | `RemediationInterceptor` returns `403 Forbidden` on every subsequent request from that IP |
| **🔒 Lock Account** | Login rejected even with correct password, red banner shown |
| **✔ Unblock IP** | Access restored instantly, no restart needed |
| **✔ Unlock Account** | Account accepts login again |

> The SOC dashboard (`/soc-dashboard`) and unblock routes are always whitelisted — analysts can never lock themselves out permanently.

---

## 📡 REST API

### `POST /api/alerts/triage`

Accepts an alert JSON body and returns a full triage response.

**Request:**
```json
{
  "srcIp": "45.83.1.10",
  "user": "admin",
  "host": "auth-server-01",
  "ruleName": "BRUTE_FORCE_LOGIN",
  "severity": "HIGH",
  "category": "intrusion",
  "assetCriticality": "HIGH",
  "source": "Suricata"
}
```

**Response:**
```json
{
  "incidentId": "INC-1717330000000",
  "severity": "HIGH",
  "riskScore": 74,
  "explanation": "...",
  "recommendation": "...",
  "mitreTechnique": "T1110 — Brute Force",
  "sourceAlert": { ... }
}
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Backend | Java 21, Spring Boot 3.2.5, Spring MVC |
| Templating | Thymeleaf |
| Build | Apache Maven |
| Email | Spring Mail + Mailtrap SMTP |
| GeoIP | ip-api.com (free tier) |
| Frontend | HTML5, CSS3, Vanilla JS (no framework) |
| Fonts | JetBrains Mono |

---

## 👤 Author

**Abdillahi Saïd Ismail**
L3 → Master's Cybersecurity — ISTIC Université de Rennes, France
Seeking alternance in cybersecurity / digital security (2025–2026)

[![GitHub](https://img.shields.io/badge/GitHub-abdillahisaidismail--arch-181717?style=flat&logo=github)](https://github.com/abdillahisaidismail-arch)

---

## 📄 License

MIT License — free to use, fork, and adapt with attribution.
