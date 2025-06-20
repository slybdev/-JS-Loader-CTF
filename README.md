# 🕵️ PCAP Malware Analysis – ServeIRC JS Loader CTF

## 📌 Scenario

The SOC team detected suspicious activity in internal network traffic. Upon investigation, it was discovered that a host had been compromised, and sensitive company information was exfiltrated. This challenge required analyzing a PCAP file to identify the attack chain, threat actor infrastructure, and methods used in the breach.

---

## 🎯 Objectives

- Identify the initial access vector  
- Extract suspicious payloads from the network traffic  
- Perform malware triage using threat intelligence tools  
- Map the attack to relevant MITRE ATT&CK techniques  
- Document Indicators of Compromise (IOCs)

---

## 🛠 Tools Used

- `Wireshark` – Network traffic analysis  
- `VirusTotal` – Malware reputation check  
- `Hybrid Analysis` – Behavioral sandboxing  
- `Wscript.exe` – Identified LOLBIN used in execution  
- `MITRE ATT&CK` – Technique classification

---

## 🔍 Investigation Steps

### 1. DNS Filtering

Used Wireshark to filter DNS queries:
dns.qry.name == "portfolio.serveirc.com"



Found suspicious domain resolution:
portfolio.serveirc.com → 62.173.142.148



---

### 2. HTTP Traffic Review

Located a GET request to:
GET /login.php HTTP/1.1
Host: portfolio.serveirc.com



Although the URI indicated a PHP page, the response content was actually a **JavaScript file**:
allegato_708[.]js


The file was disguised to evade detection.

---

### 3. Threat Intelligence & Malware Behavior

- Hashed the file → submitted to **VirusTotal** → flagged as **malicious**
- Uploaded to **Hybrid Analysis**
  - Observed execution via `wscript.exe` (LOLBIN)
  - Behavior: initiated an HTTP request to download a second-stage payload:
    ```
    GET /resources.dll
    ```
  - Detected API call: `HttpOpenRequestW`

The second payload (`resources.dll`) was also flagged as **malicious** on VirusTotal.

---

## 🧩 MITRE ATT&CK Mapping

| Tactic             | Technique                          | Description                                |
|--------------------|-------------------------------------|--------------------------------------------|
| Initial Access     | T1189 – Drive-by Compromise         | Malicious JS delivered via GET request     |
| Execution          | T1059.005 – JavaScript              | Payload executed with `wscript.exe`        |
| Defense Evasion    | T1218.005 – LOLBIN (wscript.exe)    | Used to bypass AV and execute script       |
| Command & Control  | T1105 – Ingress Tool Transfer       | Downloaded `resources.dll` from C2 server  |

---

## 📌 Indicators of Compromise (IOCs)

- **Domain:** `portfolio.serveirc.com`  
- **IP Address:** `62.173.142.148`  
- **Initial Payload:** `allegato_708.js`  
- **Second-stage File:** `resources.dll`  
- **Executable Used:** `wscript.exe`  
- **Behavioral API:** `HttpOpenRequestW`

---

## ✅ Outcome

Successfully traced the attack from DNS request to malware execution. Discovered a multi-stage infection chain using a JS loader and LOLBIN abuse. The findings emphasize the importance of:

- DNS + HTTP inspection
- MIME type mismatch detection
- Blocking LOLBIN abuse (like wscript.exe)
- Integrating threat intel into SOC workflows

---

## 🔐 Defender Recommendations

- Block domain `serveirc[.]com` at DNS level  
- Monitor for `wscript.exe` network activity  
- Alert on `.php` files serving non-HTML/JS content  
- Inspect payloads with mismatched content types  

---

## 👨‍💻 Author

**Silas Binitie**  
SOC Analyst & Blue Teamer | [LinkedIn](https://www.linkedin.com/in/silas-cybersec) • [GitHub](https://github.com/slybdev)

---

> “Always learning. Always hunting.” 🧠🔍  
#CyberSecurity #PCAPAnalysis #BlueTeam #SOC #DFIR #MalwareAnalysis #MITRE #ThreatHunting
