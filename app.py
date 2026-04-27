import time

import streamlit as st

from logic import EmailExpert, FuzzyRiskEngine, PasswordExpert, SecurityChatExpert

# Page configuration
st.set_page_config(
    page_title="CyberGuard | Hybrid Expert System",
    page_icon="CG",
    layout="wide",
)

# Load custom CSS
with open("style.css", encoding="utf-8") as f:
    st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# Initialize engines
email_expert = EmailExpert()
pwd_expert = PasswordExpert()
fuzzy_engine = FuzzyRiskEngine()
chat_expert = SecurityChatExpert()

# Session state for boot animation and chat history
if "booted" not in st.session_state:
    with st.spinner("Initializing CyberGuard Expert System..."):
        time.sleep(1.2)
    st.session_state["booted"] = True

if "chat_messages" not in st.session_state:
    st.session_state["chat_messages"] = [
        {
            "role": "assistant",
            "content": (
                "I am the CyberGuard Assistant. Ask about phishing indicators, suspicious links, "
                "password safety, MFA, or breach response. I will respond with a matched rule and confidence."
            ),
        }
    ]

# --- HEADER ---
st.markdown(
    """
<div class="app-header">
    <h1>CyberGuard</h1>
    <p class="subtitle">Phishing and Password Security Expert System</p>
</div>
""",
    unsafe_allow_html=True,
)

assessment_tab, chat_tab = st.tabs(["Risk Assessment", "Security Q&A"])

with assessment_tab:
    col1, col2 = st.columns(2, gap="large")

    with col1:
        st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
        st.subheader("Email Characteristics")
        st.write("Select the indicators identified in the email under review.")

        unknown_sender = st.checkbox("Unknown or spoofed sender address")
        malicious_links = st.checkbox("Contains links with unusual domains")
        urgency = st.checkbox("Language creating urgency or pressure")
        sensitive_info = st.checkbox("Requests sensitive information (PII or login)")

        email_factors = {
            "unknown_sender": unknown_sender,
            "malicious_links": malicious_links,
            "urgency": urgency,
            "sensitive_info_request": sensitive_info,
        }
        email_score = email_expert.evaluate(email_factors)
        st.markdown("</div>", unsafe_allow_html=True)

    with col2:
        st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
        st.subheader("Password Auditor")
        st.write("Enter a sample password for security quality estimation.")

        password = st.text_input("Test Password", type="password", placeholder="************")
        pwd_strength = pwd_expert.evaluate(password) if password else None

        if password:
            st.progress(pwd_strength, text=f"Password strength score: {int(pwd_strength * 100)}%")
            strength_text = "Strong" if pwd_strength > 0.7 else "Moderate" if pwd_strength > 0.4 else "Weak"
            st.caption(f"Classification: {strength_text}")
        else:
            st.caption("No password entered yet. Password contribution is excluded from total risk.")
        st.markdown("</div>", unsafe_allow_html=True)

    # --- LOGIC PROCESSING ---
    total_risk_val = fuzzy_engine.compute_total_risk(email_score, pwd_strength)
    risk_label = fuzzy_engine.get_risk_label(total_risk_val)
    recommendations = fuzzy_engine.get_recommendations(email_factors, pwd_strength)

    risk_class = "low-risk" if risk_label == "LOW" else "medium-risk" if risk_label == "MEDIUM" else "high-risk"

    # --- SUMMARY STRIP ---
    summary_1, summary_2, summary_3 = st.columns(3)
    summary_1.metric("Email Risk", f"{int(email_score * 100)}%")
    summary_2.metric("Password Strength", f"{int(pwd_strength * 100)}%" if pwd_strength is not None else "N/A")
    summary_3.metric("Total Security Risk", f"{int(total_risk_val * 100)}%")

    # --- RISK + RECOMMENDATIONS ---
    risk_col, rec_col = st.columns(2, gap="large")
    with risk_col:
        st.markdown(
            f"""
<div class="gauge-container">
    <div class="risk-circle {risk_class}">
        <div class="risk-label">Risk Level</div>
        <div class="risk-value">{int(total_risk_val * 100)}%</div>
        <div class="risk-label">{risk_label}</div>
    </div>
</div>
""",
            unsafe_allow_html=True,
        )
    with rec_col:
        st.markdown("### Recommendations")
        for rec in recommendations:
            st.markdown(f'<div class="rec-item">{rec}</div>', unsafe_allow_html=True)

with chat_tab:
    top_left, top_right = st.columns([5, 1])
    with top_left:
        st.caption("Ask practical questions related to phishing and password security.")
    with top_right:
        if st.button("Clear Chat", use_container_width=True):
            st.session_state["chat_messages"] = [
                {
                    "role": "assistant",
                    "content": (
                        "Chat reset complete. Ask about phishing indicators, suspicious links, "
                        "password safety, MFA, or breach response."
                    ),
                }
            ]
            st.rerun()

    for msg in st.session_state["chat_messages"]:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    user_question = st.chat_input("Ask a question...")
    if user_question:
        st.session_state["chat_messages"].append({"role": "user", "content": user_question})
        with st.chat_message("user"):
            st.markdown(user_question)

        result = chat_expert.answer_question(user_question)
        confidence_pct = int(result["confidence"] * 100)
        matched_terms = ", ".join(result["matched_keywords"]) if result["matched_keywords"] else "none"
        answer = (
            f"{result['answer']}\n\n"
            f"**Rule ID:** `{result['rule_id']}`  \n"
            f"**Confidence:** `{confidence_pct}%`  \n"
            f"**Matched Terms:** `{matched_terms}`\n\n"
            f"**Follow-up:** {result['follow_up']}"
        )
        st.session_state["chat_messages"].append({"role": "assistant", "content": answer})
        with st.chat_message("assistant"):
            st.markdown(answer)

# --- FOOTER ---
st.markdown("---")
st.caption("CyberGuard Decision Support System")
