import streamlit as st
import json
from datetime import datetime
from engine import (
    ThreatDetectionEngine, Threat, Symptom, Observation,
    SystemImpact, UserActivity, TimeContext
)
from llm import generate_threat_summary



st.set_page_config(page_title=" Cyber Threat Expert", layout="wide")
st.title(" Cyber Threat Detection Expert System")
st.markdown("---")



st.subheader("1️⃣ Select Threat Category")
threat_type = st.selectbox(
    "Select the type of cybersecurity threat:",
    ["Malware", "Phishing", "Network Intrusion", "DDoS", "Insider Threat", "Other"]
)
st.markdown("---")



st.subheader("2️⃣ Observed Symptoms")
threat_symptoms = {
    "Malware": ["Unusual CPU Usage", "Unexpected Popups", "System Slowdown", "Unauthorized File Changes", "Antivirus Disabled"],
    "Phishing": ["Suspicious Email", "Clicked Suspicious Link", "Suspicious Attachment", "Threatening Language"],
    "Network Intrusion": ["Slow Network", "Unauthorized Access", "Unusual Network Traffic", "Failed Login Attempts"],
    "DDoS": ["Service Downtime", "High Traffic Volume", "Server Timeout", "Connection Failures"],
    "Insider Threat": ["Multiple Login Failures", "Access to Restricted Files", "Suspicious Behavior", "Unusual Data Downloads"],
    "Other": []
}

symptoms = []
cols = st.columns(2)
for i, s in enumerate(threat_symptoms[threat_type]):
    if cols[i % 2].checkbox(s):
        symptoms.append(s)

if threat_type == "Other":
    custom_symptom = st.text_area("Enter custom symptoms (comma-separated):")
    if custom_symptom:
        symptoms.extend([s.strip() for s in custom_symptom.split(",") if s.strip()])
st.markdown("---")



st.subheader("3️⃣ Additional Observations")
obs_opts = ["Privilege Escalation Detected", "New Device Connected", "File Modifications Observed", "Unusual Outbound Traffic"]
observations = []
cols = st.columns(2)
for i, o in enumerate(obs_opts):
    if cols[i % 2].checkbox(o):
        observations.append(o)
custom_obs = st.text_area("Other observations:")
if custom_obs:
    observations.append(custom_obs.strip())
st.markdown("---")



st.subheader("4️⃣ System Impact & User Activity")
col1, col2 = st.columns(2)
with col1:
    selected_impact = st.selectbox("System Impact", ["None", "System Crash", "Data Loss", "Service Downtime", "Credential Leak", "Unauthorized Access"])
with col2:
    time_context = st.selectbox("Time Context", ["Business Hours", "After Hours", "Weekend", "Holiday"])

user_activities = []
cols = st.columns(3)
acts = ["Suspicious Login Detected", "Accessed Restricted Files", "Frequent File Downloads"]
for i, a in enumerate(acts):
    if cols[i % 3].checkbox(a):
        user_activities.append(a)
custom_act = st.text_input("Other suspicious activities:")
if custom_act:
    user_activities.append(custom_act.strip())
st.markdown("---")


st.subheader("5️⃣ Run Diagnosis")
if st.button("🚀 Run Threat Diagnosis", use_container_width=True):
    with st.spinner("Analyzing..."):
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

    st.success("✅ Analysis Complete")
    c1, c2, c3 = st.columns(3)
    c1.metric("Threat", report['best_fit'])
    c2.metric("Severity", report['severity'])
    c3.metric("Confidence", f"{report['confidence']}%")

    st.subheader("🛠️ Recommended Mitigation Steps")
    if report.get('mitigation_steps'):
        for step in report['mitigation_steps']:
            st.write(f"- {step}")
    else:
        st.caption("No mitigation steps suggested.")

    st.subheader("🧩 Reasoning Summary")
    if report.get('explanations'):
        for e in report['explanations']:
            st.write(f"- {e}")
    else:
        st.caption("No reasoning steps recorded.")

    st.subheader("🧠 Alternative Threat Possibilities")
    if report['alternatives']:
        for alt in report['alternatives']:
            st.write(f"• {alt}")
    else:
        st.caption("No alternatives found.")

    
    st.markdown("---")
    st.subheader("🤖 AI-Powered Threat Summary")
    try:
        summary = generate_threat_summary(report)
        st.success("LLM Analysis Complete")
        st.write(summary)
    except Exception as e:
        st.error(f"LLM Error: {str(e)}")
        st.info("Ensure your GROQ_API_KEY is set.")

    st.download_button(
        "📥 Download Threat Report (JSON)",
        json.dumps(report, indent=2),
        file_name=f"threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )
else:
    st.info("🧭 Fill the details and click **Run Threat Diagnosis** to start.")
