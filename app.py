import streamlit as st
import json
from datetime import datetime
from engine import (
    ThreatDetectionEngine, Threat, Symptom, Observation,
    SystemImpact, UserActivity, TimeContext
)

# --------------------------
# Page Setup
# --------------------------
st.set_page_config(page_title="🛡️ Cyber Threat Expert", layout="wide")
st.title("🛡️ Cyber Threat Detection Expert System")
st.caption("A smart rule-based cybersecurity analysis assistant")

st.markdown("---")

# --------------------------
# 1️⃣ Threat Category
# --------------------------
st.subheader("1️⃣ Select Threat Category")
threat_type = st.selectbox(
    "Threat Type",
    ["Malware", "Phishing", "Network Intrusion", "DDoS", "Insider Threat"],
    index=0
)

st.markdown("---")

# --------------------------
# 2️⃣ Observed Symptoms
# --------------------------
st.subheader("2️⃣ Observed Symptoms")
symptoms = []
threat_symptoms = {
    "Malware": ["Unusual CPU Usage", "Unexpected Popups", "System Slowdown", "Unauthorized File Changes", "Antivirus Disabled"],
    "Phishing": ["Suspicious Email", "Clicked Suspicious Link", "Suspicious Attachment", "Threatening Language"],
    "Network Intrusion": ["Slow Network", "Unauthorized Access", "Unusual Network Traffic", "Failed Login Attempts"],
    "DDoS": ["Service Downtime", "High Traffic Volume", "Server Timeout", "Connection Failures"],
    "Insider Threat": ["Multiple Login Failures", "Access to Restricted Files", "Suspicious Behavior", "Unusual Data Downloads"]
}
cols = st.columns(2)
for i, s in enumerate(threat_symptoms[threat_type]):
    if cols[i % 2].checkbox(s):
        symptoms.append(s)

st.markdown("---")

# --------------------------
# 3️⃣ Additional Observations
# --------------------------
st.subheader("3️⃣ Additional Observations")
observations = []
obs_opts = [
    "Privilege Escalation Detected",
    "New Device Connected",
    "File Modifications Observed",
    "Unusual Outbound Traffic"
]
obs_cols = st.columns(2)
for i, o in enumerate(obs_opts):
    if obs_cols[i % 2].checkbox(o):
        observations.append(o)

st.markdown("---")

# --------------------------
# 4️⃣ System Impact & User Activity
# --------------------------
st.subheader("4️⃣ System Impact & User Activity")
col1, col2 = st.columns(2)
with col1:
    selected_impact = st.selectbox(
        "System Impact",
        ["None", "System Crash", "Data Loss", "Service Downtime", "Credential Leak", "Unauthorized Access"]
    )
with col2:
    time_context = st.selectbox(
        "Time Context",
        ["Business Hours", "After Hours", "Weekend", "Holiday"]
    )

st.caption("👤 User Activity Indicators")
user_activities = []
act_cols = st.columns(3)
act_opts = [
    "Suspicious Login Detected",
    "Accessed Restricted Files",
    "Frequent File Downloads"
]
for i, a in enumerate(act_opts):
    if act_cols[i % 3].checkbox(a):
        user_activities.append(a)

st.markdown("---")

# --------------------------
# 5️⃣ Run Diagnosis Button
# --------------------------
analyze_button = st.button("🚀 Run Threat Diagnosis", use_container_width=True)

# --------------------------
# RUN ENGINE & DISPLAY RESULTS
# --------------------------
if analyze_button:
    with st.spinner("🔍 Analyzing... please wait"):
        engine = ThreatDetectionEngine()
        engine.reset()

        engine.declare(Threat(threat=threat_type))
        for s in symptoms:
            engine.declare(Symptom(symptom=s))
        for o in observations:
            engine.declare(Observation(observation=o))
        if selected_impact != "None":
            engine.declare(SystemImpact(impact=selected_impact))
        for u in user_activities:
            engine.declare(UserActivity(activity=u))
        engine.declare(TimeContext(time=time_context))

        engine.run()
        report = engine.report

    # --------------------------
    # RESULTS
    # --------------------------
    st.success("✅ Analysis Complete")

    col1, col2, col3 = st.columns(3)
    col1.metric("Threat", report['best_fit'])
    col2.metric("Severity", report['severity'])
    col3.metric("Confidence", f"{report['confidence']}%")

    severity_msg = {
        "Critical": "🚨 Immediate Action Required",
        "High": "⚠️ High Severity - Respond Quickly",
        "Medium": "ℹ️ Moderate Risk - Investigate",
        "Low": "🟢 Low Risk - Monitor"
    }
    st.info(severity_msg.get(report['severity'], "Unknown Severity"))

    if report.get('alternatives'):
        with st.expander("🔄 Alternative Possibilities"):
            for alt in report['alternatives']:
                st.write(f"• {alt}")

    with st.expander("🛠️ Recommended Mitigation Steps", expanded=True):
        for i, step in enumerate(report['mitigation_steps'], 1):
            st.write(f"{i}. {step}")

    if report.get('scores'):
        with st.expander("📊 Confidence Scores"):
            for threat, score in report['scores'].items():
                percent = min(int((score / 200) * 100), 100)
                st.progress(percent / 100)
                st.caption(f"{threat}: {percent}%")

    # Export option
    report_json = json.dumps(report, indent=2)
    st.download_button(
        "📥 Download Report (JSON)",
        report_json,
        file_name=f"threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        use_container_width=True
    )

else:
    st.info("🧭 Select threat details and click **Run Threat Diagnosis** to begin.")
