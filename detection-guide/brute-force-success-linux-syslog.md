# 🛡️ Rule: CUSTOM: Brute Force SUCCESS - Linux Syslog

---

## 📖 Description
Identifies successful brute force attacks against Linux systems by analyzing syslog authentication events.

**Platform:** Linux  
**MITRE ATT&CK Techniques:** T1110

---

## 🔎 KQL Query

```kql
Syslog
| where TimeGenerated >= ago(24h)
| where ProcessName == "sshd"
| where SyslogMessage has_any ("Failed password","Accepted password")
| extend SrcIP = extract(@"\b\d{1,3}(?:\.\d{1,3}){3}\b", 0, SyslogMessage)
| where SrcIP == "[IP]"   
| order by TimeGenerated asc
````

---

## 🔗 External Resources

* **VirusTotal** – [https://www.virustotal.com](https://www.virustotal.com)
  Check if the source IP, domain, or file hash is already known as malicious.

* **AbuseIPDB** – [https://www.abuseipdb.com](https://www.abuseipdb.com)
  Look up the source IP address to see community reports of brute force, spam, or malicious activity.