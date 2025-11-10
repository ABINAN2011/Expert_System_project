from experta import KnowledgeEngine, Fact, Rule, AND, OR
from datetime import datetime

# ------------------------------
# Enhanced Facts for Cybersecurity Threats
# ------------------------------
class Threat(Fact): pass
class Symptom(Fact): pass
class Observation(Fact): pass
class SystemImpact(Fact): pass
class UserActivity(Fact): pass
class TimeContext(Fact): pass
class NetworkBehavior(Fact): pass
class FileActivity(Fact): pass


# ------------------------------
# Enhanced Cybersecurity Threat Detection Engine
# ------------------------------
class ThreatDetectionEngine(KnowledgeEngine):
    def __init__(self):
        super().__init__()
        self.report = {
            "best_fit": None,
            "alternatives": [],
            "explanations": [],
            "scores": {},
            "confidence": 0,
            "severity": "Unknown",
            "mitigation_steps": [],
            "indicators": [],
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        self.severity_thresholds = {
            "Critical": 150,
            "High": 100,
            "Medium": 50,
            "Low": 20
        }

    def explain(self, message):
        self.report['explanations'].append(message)

    def add_score(self, diagnosis, points):
        if diagnosis in self.report['scores']:
            self.report['scores'][diagnosis] += points
        else:
            self.report['scores'][diagnosis] = points

    def add_indicator(self, indicator):
        if indicator not in self.report['indicators']:
            self.report['indicators'].append(indicator)

    def add_mitigation(self, step):
        if step not in self.report['mitigation_steps']:
            self.report['mitigation_steps'].append(step)

    # =====================================================
    # 1️⃣  ENHANCED MALWARE RULES
    # =====================================================
    @Rule(AND(Threat(threat='Malware'), Symptom(symptom='Unusual CPU Usage')))
    def malware_cpu(self):
        self.add_score('Malware Infection', 40)
        self.add_score('Cryptominer', 45)
        self.add_indicator("High CPU usage detected")
        self.explain("High CPU usage indicates hidden malware processes or cryptomining.")
        self.add_mitigation("Run full system antivirus scan")
        self.add_mitigation("Check Task Manager for suspicious processes")

    @Rule(AND(Threat(threat='Malware'), Symptom(symptom='Unusual CPU Usage'), 
              TimeContext(time='After Hours')))
    def malware_cpu_afterhours(self):
        self.add_score('Cryptominer', 30)
        self.add_score('Advanced Persistent Threat', 25)
        self.explain("After-hours CPU spikes suggest automated malware activity.")
        self.add_indicator("Off-hours suspicious activity")

    @Rule(AND(Threat(threat='Malware'), Symptom(symptom='Unexpected Popups')))
    def malware_popups(self):
        self.add_score('Adware Infection', 50)
        self.add_score('Phishing Attempt', 15)
        self.add_score('Browser Hijacker', 40)
        self.add_indicator("Unwanted popup advertisements")
        self.explain("Unexpected popups indicate adware, browser hijacker, or phishing malware.")
        self.add_mitigation("Clear browser cache and remove suspicious extensions")
        self.add_mitigation("Run adware removal tool")

    @Rule(AND(Threat(threat='Malware'), Observation(observation='File Changes')))
    def malware_file_change(self):
        self.add_score('Ransomware', 70)
        self.add_score('Malware Infection', 25)
        self.add_score('Trojan', 30)
        self.add_indicator("Unauthorized file modifications detected")
        self.explain("Unauthorized file encryption or deletion strongly suggests ransomware.")
        self.add_mitigation("IMMEDIATELY disconnect from network")
        self.add_mitigation("Do not pay ransom - contact security team")
        self.add_mitigation("Restore from clean backups if available")

    @Rule(AND(Threat(threat='Malware'), FileActivity(activity='Mass Encryption')))
    def malware_encryption(self):
        self.add_score('Ransomware', 90)
        self.add_indicator("Mass file encryption in progress")
        self.explain("Mass file encryption is definitive ransomware behavior.")
        self.add_mitigation("CRITICAL: Isolate system immediately")
        self.add_mitigation("Preserve forensic evidence")

    @Rule(AND(SystemImpact(impact='Data Loss'), Threat(threat='Malware')))
    def malware_data_loss(self):
        self.add_score('Ransomware', 75)
        self.add_score('Wiper Malware', 40)
        self.add_indicator("Data loss or corruption detected")
        self.explain("Data loss is a strong indicator of ransomware or destructive malware.")
        self.add_mitigation("Check for ransom notes or messages")

    @Rule(AND(UserActivity(activity='External Device Used'), Threat(threat='Malware')))
    def malware_usb(self):
        self.add_score('Worm Infection', 45)
        self.add_score('USB-based Malware', 50)
        self.add_indicator("External device usage detected")
        self.explain("Malware can spread through infected USB or external devices.")
        self.add_mitigation("Scan all external devices before use")
        self.add_mitigation("Disable autorun for removable media")

    @Rule(AND(Threat(threat='Malware'), NetworkBehavior(behavior='Unusual Outbound Traffic')))
    def malware_c2_communication(self):
        self.add_score('Botnet Activity', 60)
        self.add_score('Data Exfiltration', 55)
        self.add_score('Trojan', 50)
        self.add_indicator("Suspicious outbound network traffic")
        self.explain("Unusual outbound traffic suggests command-and-control communication.")
        self.add_mitigation("Block suspicious IP addresses")
        self.add_mitigation("Analyze network logs for IOCs")

    @Rule(AND(Threat(threat='Malware'), Symptom(symptom='System Slowdown'),
              NetworkBehavior(behavior='Unusual Outbound Traffic')))
    def malware_advanced_threat(self):
        self.add_score('Advanced Persistent Threat', 70)
        self.explain("Combined slowdown and network anomalies indicate sophisticated malware.")
        self.add_indicator("Multiple correlated threat indicators")

    # =====================================================
    # 2️⃣  ENHANCED PHISHING RULES
    # =====================================================
    @Rule(AND(Threat(threat='Phishing'), Symptom(symptom='Suspicious Email'), 
              Observation(observation='Link Clicked')))
    def phishing_click(self):
        self.add_score('Phishing Attack', 85)
        self.add_score('Credential Harvesting', 40)
        self.add_indicator("User clicked suspicious email link")
        self.explain("User clicked a suspicious link – classic phishing indicator.")
        self.add_mitigation("Change all passwords immediately")
        self.add_mitigation("Enable 2FA on all accounts")
        self.add_mitigation("Report email to security team")

    @Rule(AND(Threat(threat='Phishing'), Symptom(symptom='Suspicious Email')))
    def phishing_email(self):
        self.add_score('Phishing Attempt', 45)
        self.add_score('Spear Phishing', 30)
        self.add_indicator("Suspicious email received")
        self.explain("Suspicious emails suggest a phishing attempt.")
        self.add_mitigation("Do not click links or download attachments")
        self.add_mitigation("Verify sender through separate communication channel")

    @Rule(AND(Threat(threat='Phishing'), Symptom(symptom='Suspicious Email'),
              Observation(observation='Attachment Opened')))
    def phishing_attachment(self):
        self.add_score('Malware Delivery', 75)
        self.add_score('Phishing Attack', 40)
        self.add_indicator("Malicious attachment opened")
        self.explain("Opening phishing attachments often delivers malware payloads.")
        self.add_mitigation("Run immediate malware scan")
        self.add_mitigation("Quarantine the system")

    @Rule(AND(UserActivity(activity='Credential Leak'), Threat(threat='Phishing')))
    def phishing_credentials(self):
        self.add_score('Credential Theft', 80)
        self.add_score('Account Compromise', 70)
        self.add_indicator("Potential credential compromise")
        self.explain("Phishing may have led to credential leakage.")
        self.add_mitigation("URGENT: Force password reset")
        self.add_mitigation("Review account activity logs")
        self.add_mitigation("Enable MFA immediately")

    @Rule(AND(Threat(threat='Phishing'), TimeContext(time='Urgent Request')))
    def phishing_urgency(self):
        self.add_score('Spear Phishing', 35)
        self.add_score('Business Email Compromise', 40)
        self.add_indicator("Email contains urgency tactics")
        self.explain("Urgency and pressure tactics are common phishing techniques.")

    # =====================================================
    # 3️⃣  ENHANCED NETWORK INTRUSION RULES
    # =====================================================
    @Rule(AND(Threat(threat='Network Intrusion'), Symptom(symptom='Slow Network')))
    def network_slow(self):
        self.add_score('Network Intrusion', 40)
        self.add_score('Network Scanning', 35)
        self.add_indicator("Network performance degradation")
        self.explain("Abnormal network latency can indicate scanning or intrusion.")
        self.add_mitigation("Monitor network traffic patterns")
        self.add_mitigation("Check firewall logs")

    @Rule(AND(Threat(threat='Network Intrusion'), Observation(observation='New Device Connected')))
    def network_device(self):
        self.add_score('Unauthorized Access', 65)
        self.add_score('Rogue Device', 60)
        self.add_indicator("Unrecognized device on network")
        self.explain("A new, unrecognized device may signal an intrusion attempt.")
        self.add_mitigation("Identify and isolate unknown device")
        self.add_mitigation("Review network access controls")

    @Rule(AND(UserActivity(activity='Accessing Restricted Files'), 
              Threat(threat='Network Intrusion')))
    def network_access(self):
        self.add_score('Insider Threat', 35)
        self.add_score('Network Breach', 50)
        self.add_score('Privilege Escalation', 40)
        self.add_indicator("Unauthorized access to restricted resources")
        self.explain("Restricted access attempts indicate insider activity or breach.")
        self.add_mitigation("Review user access privileges")
        self.add_mitigation("Investigate user activity timeline")

    @Rule(AND(Threat(threat='Network Intrusion'), 
              NetworkBehavior(behavior='Port Scanning')))
    def network_port_scan(self):
        self.add_score('Network Reconnaissance', 70)
        self.add_score('Precursor to Attack', 55)
        self.add_indicator("Port scanning activity detected")
        self.explain("Port scanning is reconnaissance before a larger attack.")
        self.add_mitigation("Block scanning source IP")
        self.add_mitigation("Increase monitoring and alerting")

    @Rule(AND(Threat(threat='Network Intrusion'), 
              NetworkBehavior(behavior='Lateral Movement')))
    def network_lateral_movement(self):
        self.add_score('Advanced Persistent Threat', 85)
        self.add_score('Network Breach', 75)
        self.add_indicator("Lateral movement across network")
        self.explain("Lateral movement indicates established network compromise.")
        self.add_mitigation("Segment network immediately")
        self.add_mitigation("Revoke compromised credentials")

    # =====================================================
    # 4️⃣  ENHANCED DDOS ATTACK RULES
    # =====================================================
    @Rule(AND(Threat(threat='DDoS'), Symptom(symptom='Slow Network'), 
              SystemImpact(impact='Service Downtime')))
    def ddos_attack(self):
        self.add_score('DDoS Attack', 95)
        self.add_indicator("Service unavailability with network saturation")
        self.explain("Service downtime and high latency definitively point to DDoS attack.")
        self.add_mitigation("Enable DDoS mitigation service")
        self.add_mitigation("Contact ISP for traffic filtering")
        self.add_mitigation("Implement rate limiting")

    @Rule(AND(Threat(threat='DDoS'), Observation(observation='Large Data Transfer')))
    def ddos_transfer(self):
        self.add_score('DDoS Attack', 60)
        self.add_score('Bandwidth Saturation', 55)
        self.add_indicator("Abnormal traffic volume")
        self.explain("Unusually high data transfer volume is a DDoS indicator.")
        self.add_mitigation("Analyze traffic sources")
        self.add_mitigation("Block malicious IP ranges")

    @Rule(AND(Threat(threat='DDoS'), NetworkBehavior(behavior='SYN Flood')))
    def ddos_syn_flood(self):
        self.add_score('DDoS Attack', 85)
        self.add_indicator("SYN flood attack detected")
        self.explain("SYN flood is a common DDoS technique targeting network stack.")
        self.add_mitigation("Enable SYN cookies")
        self.add_mitigation("Adjust firewall SYN timeout")

    @Rule(AND(Threat(threat='DDoS'), NetworkBehavior(behavior='Application Layer Attack')))
    def ddos_application_layer(self):
        self.add_score('Application Layer DDoS', 80)
        self.add_indicator("Layer 7 attack targeting application")
        self.explain("Application-layer attacks are harder to detect and mitigate.")
        self.add_mitigation("Implement web application firewall")
        self.add_mitigation("Use CAPTCHA challenges")

    # =====================================================
    # 5️⃣  ENHANCED INSIDER THREAT RULES
    # =====================================================
    @Rule(AND(Threat(threat='Insider Threat'), 
              UserActivity(activity='Multiple Login Attempts')))
    def insider_login(self):
        self.add_score('Credential Misuse', 65)
        self.add_score('Brute Force Attempt', 45)
        self.add_indicator("Multiple failed login attempts")
        self.explain("Repeated failed logins from internal users indicate credential misuse.")
        self.add_mitigation("Lock account temporarily")
        self.add_mitigation("Require password reset")
        self.add_mitigation("Review user behavior patterns")

    @Rule(AND(Threat(threat='Insider Threat'), 
              Observation(observation='Privilege Escalation')))
    def insider_privilege(self):
        self.add_score('Insider Threat', 85)
        self.add_score('Account Compromise', 50)
        self.add_indicator("Unauthorized privilege elevation")
        self.explain("Privilege escalation suggests malicious internal activity.")
        self.add_mitigation("Revoke elevated privileges immediately")
        self.add_mitigation("Conduct security investigation")
        self.add_mitigation("Review access control policies")

    @Rule(AND(Threat(threat='Insider Threat'), 
              SystemImpact(impact='Unauthorized Access')))
    def insider_access(self):
        self.add_score('Insider Threat', 75)
        self.add_score('Data Theft', 60)
        self.add_indicator("Unauthorized system access")
        self.explain("Unauthorized access from known users implies insider compromise.")
        self.add_mitigation("Investigate access patterns")
        self.add_mitigation("Review data access logs")

    @Rule(AND(Threat(threat='Insider Threat'), 
              FileActivity(activity='Mass Download')))
    def insider_data_exfil(self):
        self.add_score('Data Exfiltration', 90)
        self.add_score('Insider Threat', 70)
        self.add_indicator("Mass data download detected")
        self.explain("Large-scale downloading indicates data theft attempt.")
        self.add_mitigation("Block data transfer immediately")
        self.add_mitigation("Preserve audit logs")
        self.add_mitigation("Initiate incident response")

    @Rule(AND(Threat(threat='Insider Threat'), 
              TimeContext(time='After Hours'),
              FileActivity(activity='Sensitive Data Access')))
    def insider_suspicious_timing(self):
        self.add_score('Insider Threat', 60)
        self.explain("After-hours access to sensitive data raises suspicion.")
        self.add_indicator("Off-hours sensitive data access")
        self.add_mitigation("Verify user authorization")

    # =====================================================
    # 6️⃣  CORRELATION RULES (Multiple threat indicators)
    # =====================================================
    @Rule(AND(NetworkBehavior(behavior='Unusual Outbound Traffic'),
              FileActivity(activity='Mass Encryption')))
    def correlation_ransomware_exfil(self):
        self.add_score('Ransomware', 50)
        self.add_score('Data Exfiltration', 45)
        self.explain("Combined encryption and data transfer suggests ransomware with exfiltration.")
        self.add_indicator("Double extortion ransomware pattern")

    @Rule(AND(UserActivity(activity='Multiple Login Attempts'),
              NetworkBehavior(behavior='Lateral Movement')))
    def correlation_breach(self):
        self.add_score('Network Breach', 65)
        self.add_score('Advanced Persistent Threat', 55)
        self.explain("Failed logins with lateral movement indicate active breach.")
        self.add_indicator("Active compromise in progress")

    # =====================================================
    # FINAL DECISION ENGINE
    # =====================================================
    @Rule()
    def decide(self):
        if not self.report['scores']:
            self.report['best_fit'] = "Insufficient Data - Monitor System"
            self.report['confidence'] = 0
            self.report['severity'] = "Unknown"
            self.explain("No sufficient indicators found. Continue monitoring system.")
            self.add_mitigation("Increase logging and monitoring")
            self.add_mitigation("Review security baselines")
            return

        # Sort scores
        sorted_scores = sorted(self.report['scores'].items(), 
                              key=lambda x: x[1], reverse=True)
        
        # Determine best fit
        self.report['best_fit'] = sorted_scores[0][0]
        best_score = sorted_scores[0][1]
        
        # Calculate confidence (0-100%)
        total_possible = 200  # Rough maximum
        self.report['confidence'] = min(int((best_score / total_possible) * 100), 99)
        
        # Determine severity
        for severity, threshold in sorted(self.severity_thresholds.items(), 
                                         key=lambda x: x[1], reverse=True):
            if best_score >= threshold:
                self.report['severity'] = severity
                break
        else:
            self.report['severity'] = "Low"
        
        # Add alternatives
        self.report['alternatives'] = [d for d, s in sorted_scores[1:4]]
        
        self.explain(f"Best-fit diagnosis: {self.report['best_fit']} "
                    f"(Confidence: {self.report['confidence']}%, "
                    f"Severity: {self.report['severity']})")