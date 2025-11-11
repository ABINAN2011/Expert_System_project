from experta import KnowledgeEngine, Fact, Rule, AND
from datetime import datetime


class Threat(Fact): pass
class Symptom(Fact): pass
class Observation(Fact): pass
class SystemImpact(Fact): pass
class UserActivity(Fact): pass
class TimeContext(Fact): pass
class NetworkBehavior(Fact): pass
class FileActivity(Fact): pass


class ThreatDetectionEngine(KnowledgeEngine):
    def __init__(self):
        super().__init__()
        self.report = {
            "best_fit": None,
            "alternatives": [],
            "diagnosis_explanations": {},
            "explanations": [],
            "scores": {},
            "confidence": 0,
            "severity": "Unknown",
            "mitigation_steps": [],
            "indicators": [],
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        self.severity_thresholds = {
            "Critical": 120,
            "High": 80,
            "Medium": 40,
            "Low": 10
        }


    def explain(self, message):
        self.report['explanations'].append(message)

    def add_score(self, diagnosis, points):
        self.report['scores'][diagnosis] = self.report['scores'].get(diagnosis, 0) + points

    def add_indicator(self, indicator):
        if indicator not in self.report['indicators']:
            self.report['indicators'].append(indicator)

    def add_mitigation(self, step, explanation=None):
        if step not in self.report['mitigation_steps']:
            self.report['mitigation_steps'].append(step)
        if explanation:
            self.report.setdefault('mitigation_details', {})[step] = explanation

    def add_diagnosis_explanation(self, diagnosis, message):
        if diagnosis not in self.report.get('diagnosis_explanations', {}):
            self.report.setdefault('diagnosis_explanations', {})[diagnosis] = []
        if message not in self.report['diagnosis_explanations'][diagnosis]:
            self.report['diagnosis_explanations'][diagnosis].append(message)


    @Rule(AND(Threat(threat='Malware'), Symptom(symptom='Unusual CPU Usage')))
    def rule_malware_cpu(self):
        self.add_score('Malware Infection', 50)
        self.add_diagnosis_explanation('Malware Infection', "High CPU usage may indicate malware or cryptomining.")
        self.add_score('Cryptominer', 60)
        self.add_diagnosis_explanation('Cryptominer', "High sustained CPU usage often indicates hidden cryptomining.")
        self.add_indicator("High CPU usage detected")
        self.explain("Continuous CPU spikes suggest malware or cryptomining.")
        self.add_mitigation("Run full antivirus scan", "Full scan isolates CPU-intensive malware.")
        self.add_mitigation("Inspect running processes", "Identify hidden mining or malware executables.")

    @Rule(AND(Threat(threat='Malware'), Symptom(symptom='Unexpected Popups')))
    def rule_malware_popups(self):
        self.add_score('Malware Infection', 40)
        self.add_diagnosis_explanation('Malware Infection', "Unexpected popups often indicate adware or trojans.")
        self.add_indicator("Unexpected popups observed")
        self.add_mitigation("Run malware removal tool", "Removes popup-generating malware.")

    @Rule(AND(Threat(threat='Malware'), Symptom(symptom='System Slowdown')))
    def rule_malware_slowdown(self):
        self.add_score('Malware Infection', 35)
        self.add_diagnosis_explanation('Malware Infection', "System slowdown may be caused by background malware.")
        self.add_indicator("System performance degraded")
        self.add_mitigation("Check running processes", "Identify CPU or memory hogging malware.")

    @Rule(AND(Threat(threat='Malware'), Symptom(symptom='Unauthorized File Changes')))
    def rule_malware_file_changes(self):
        self.add_score('Malware Infection', 50)
        self.add_diagnosis_explanation('Malware Infection', "Malware may alter or encrypt files.")
        self.add_indicator("File modifications detected")
        self.add_mitigation("Restore files from backup", "Ensure integrity of system data.")

    @Rule(AND(Threat(threat='Malware'), Symptom(symptom='Antivirus Disabled')))
    def rule_malware_av_disabled(self):
        self.add_score('Malware Infection', 60)
        self.add_diagnosis_explanation('Malware Infection', "Some malware disables antivirus protection to evade detection.")
        self.add_indicator("Antivirus disabled")
        self.add_mitigation("Re-enable antivirus and scan system", "Detect and remove malware.")

    # -------- Phishing Rules --------
    @Rule(AND(Threat(threat='Phishing'), Symptom(symptom='Suspicious Email')))
    def rule_phishing_email(self):
        self.add_score('Phishing Attempt', 55)
        self.add_diagnosis_explanation('Phishing Attempt', "Suspicious sender or fake links indicate phishing.")
        self.add_indicator("Suspicious email received")
        self.explain("Emails with urgent tone or fake links are classic phishing indicators.")
        self.add_mitigation("Report to security team", "Enable organization-wide alerting.")
        self.add_mitigation("Do not click links", "Verify sender identity first.")

    @Rule(AND(Threat(threat='Phishing'), Symptom(symptom='Clicked Suspicious Link')))
    def rule_phishing_link(self):
        self.add_score('Phishing Attempt', 50)
        self.add_diagnosis_explanation('Phishing Attempt', "Clicking unknown links may compromise credentials.")
        self.add_indicator("Suspicious link clicked")
        self.add_mitigation("Change passwords immediately", "Prevent unauthorized access.")

    @Rule(AND(Threat(threat='Phishing'), Symptom(symptom='Suspicious Attachment')))
    def rule_phishing_attachment(self):
        self.add_score('Phishing Attempt', 55)
        self.add_diagnosis_explanation('Phishing Attempt', "Attachments may contain malware or ransomware.")
        self.add_indicator("Suspicious attachment opened")
        self.add_mitigation("Run attachment in sandbox or delete", "Avoid system compromise.")

    @Rule(AND(Threat(threat='Phishing'), Symptom(symptom='Threatening Language')))
    def rule_phishing_threat(self):
        self.add_score('Phishing Attempt', 45)
        self.add_diagnosis_explanation('Phishing Attempt', "Urgent or threatening language is typical of phishing.")
        self.add_indicator("Threatening language in email")
        self.add_mitigation("Report email to security team", "Enable alerts to prevent compromise.")


    @Rule(AND(Threat(threat='Network Intrusion'), Symptom(symptom='Slow Network')))
    def rule_network_slow(self):
        self.add_score('Network Reconnaissance', 30)
        self.add_diagnosis_explanation('Network Reconnaissance', "Slow network may indicate scanning or attack traffic.")
        self.add_indicator("Network slowdown detected")
        self.add_mitigation("Monitor network traffic", "Identify abnormal patterns.")

    @Rule(AND(Threat(threat='Network Intrusion'), Symptom(symptom='Unauthorized Access')))
    def rule_network_unauthorized(self):
        self.add_score('Unauthorized Access', 60)
        self.add_diagnosis_explanation('Unauthorized Access', "Attempted access to restricted resources detected.")
        self.add_indicator("Unauthorized access attempts")
        self.add_mitigation("Block suspicious accounts/IPs", "Prevent further intrusion.")

    @Rule(AND(Threat(threat='Network Intrusion'), Symptom(symptom='Unusual Network Traffic')))
    def rule_network_traffic(self):
        self.add_score('Network Reconnaissance', 50)
        self.add_diagnosis_explanation('Network Reconnaissance', "Unexpected traffic patterns may indicate scanning or malware C2.")
        self.add_indicator("Unusual outbound/inbound traffic")
        self.add_mitigation("Enable IDS/IPS", "Detect and block suspicious traffic.")

    @Rule(AND(Threat(threat='Network Intrusion'), Symptom(symptom='Failed Login Attempts')))
    def rule_network_failed_login(self):
        self.add_score('Unauthorized Access', 40)
        self.add_diagnosis_explanation('Unauthorized Access', "Multiple failed logins suggest brute-force attack.")
        self.add_indicator("Multiple failed login attempts")
        self.add_mitigation("Lock affected accounts temporarily", "Prevent further brute-force attempts.")

    # -------- DDoS Rules --------
    @Rule(AND(Threat(threat='DDoS'), Symptom(symptom='High Traffic Volume')))
    def rule_ddos_high_traffic(self):
        self.add_score('DDoS Attack', 70)
        self.add_diagnosis_explanation('DDoS Attack', "Abnormally high traffic may indicate DDoS attack.")
        self.add_indicator("High traffic volume")
        self.add_mitigation("Activate DDoS mitigation services", "Reduce load on servers.")

    @Rule(AND(Threat(threat='DDoS'), Symptom(symptom='Service Downtime')))
    def rule_ddos_downtime(self):
        self.add_score('DDoS Attack', 50)
        self.add_diagnosis_explanation('DDoS Attack', "Service downtime may indicate a DDoS attack.")
        self.add_indicator("Service downtime observed")
        self.add_mitigation("Check server logs and mitigate traffic", "Investigate traffic source.")

    @Rule(AND(Threat(threat='DDoS'), Symptom(symptom='Server Timeout')))
    def rule_ddos_timeout(self):
        self.add_score('DDoS Attack', 40)
        self.add_diagnosis_explanation('DDoS Attack', "Server timeout can indicate high load from attack.")
        self.add_indicator("Server timeout observed")
        self.add_mitigation("Activate traffic filtering", "Reduce malicious traffic impact.")

    @Rule(AND(Threat(threat='DDoS'), Symptom(symptom='Connection Failures')))
    def rule_ddos_connection_failures(self):
        self.add_score('DDoS Attack', 30)
        self.add_diagnosis_explanation('DDoS Attack', "Connection failures may indicate network flooding.")
        self.add_indicator("Connection failures observed")
        self.add_mitigation("Check firewall rules", "Block suspicious IPs.")


    @Rule(AND(Threat(threat='Insider Threat'), Symptom(symptom='Multiple Login Failures')))
    def rule_insider_login_failures(self):
        self.add_score('Insider Threat', 40)
        self.add_diagnosis_explanation('Insider Threat', "Repeated failed logins may indicate malicious insider activity.")
        self.add_indicator("Multiple login failures")
        self.add_mitigation("Monitor user accounts", "Investigate suspicious behavior.")

    @Rule(AND(Threat(threat='Insider Threat'), Symptom(symptom='Access to Restricted Files')))
    def rule_insider_restricted_access(self):
        self.add_score('Insider Threat', 60)
        self.add_diagnosis_explanation('Insider Threat', "Accessing restricted files may indicate malicious insider activity.")
        self.add_indicator("Restricted file access")
        self.add_mitigation("Alert security team", "Investigate employee actions.")

    @Rule(AND(Threat(threat='Insider Threat'), Symptom(symptom='Suspicious Behavior')))
    def rule_insider_behavior(self):
        self.add_score('Insider Threat', 50)
        self.add_diagnosis_explanation('Insider Threat', "Suspicious behavior detected; could be insider threat.")
        self.add_indicator("Suspicious behavior observed")
        self.add_mitigation("Monitor and audit activities", "Track suspicious employee actions.")

    @Rule(AND(Threat(threat='Insider Threat'), Symptom(symptom='Unusual Data Downloads')))
    def rule_insider_data_download(self):
        self.add_score('Insider Threat', 45)
        self.add_diagnosis_explanation('Insider Threat', "Unusual data downloads may indicate data exfiltration.")
        self.add_indicator("Large or unusual downloads")
        self.add_mitigation("Restrict data access", "Prevent unauthorized data exfiltration.")

 
    @Rule()
    def finalize_report(self):
        if not self.report['scores']:
            self.report.update({
                "best_fit": "Insufficient Data",
                "confidence": 0,
                "severity": "Unknown"
            })
            self.explain("No conclusive indicators found. Continue monitoring.")
            self.add_mitigation("Increase logging depth", "Collect detailed telemetry for correlation.")
        else:
            sorted_scores = sorted(self.report['scores'].items(), key=lambda x: x[1], reverse=True)
            best_fit, best_score = sorted_scores[0]
            total_score = sum(score for _, score in sorted_scores)
            self.report['best_fit'] = best_fit
            self.report['alternatives'] = [d for d, _ in sorted_scores[1:4]]
            self.report['confidence'] = min(int((best_score / total_score) * 100), 99)

            for level, threshold in self.severity_thresholds.items():
                if best_score >= threshold:
                    self.report['severity'] = level
                    break

            self.explain(f"✅ Final Assessment: {best_fit} "
                         f"(Confidence: {self.report['confidence']}%, Severity: {self.report['severity']}).")

        self.report["summary_text"] = self._generate_summary()

 
    def _generate_summary(self):
        best = self.report.get('best_fit')
        diag_reasons = self.report.get('diagnosis_explanations', {})
        best_reasons = diag_reasons.get(best, [])
        alt_text = "\n".join([f"• {a}" for a in self.report['alternatives']]) or "None"

        return f"""
🧠 **Cyber Threat Analysis Summary**
-----------------------------------
**Detected Threat:** {best}
**Severity:** {self.report['severity']}
**Confidence:** {self.report['confidence']}%

**Indicators:** {', '.join(self.report['indicators']) or 'None'}
**Alternative Possibilities:** {alt_text}

🕒 Generated: {self.report['timestamp']}
"""
