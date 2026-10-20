import os
import requests
import streamlit as st
from datetime import datetime

st.set_page_config(
    page_title="UPI Safety Coach AI",
    page_icon="🛡️",
    layout="wide",
)

NAVY = "#0b1730"
PANEL = "#122344"
MINT = "#56e0c0"
MUTED = "#a9b8d5"

st.markdown(f"""
<style>
.stApp {{
  background: radial-gradient(circle at 80% 0%, #193663 0%, {NAVY} 48%);
  color: #f4f7ff;
}}
.block-container {{max-width: 1120px; padding-top: 2rem; padding-bottom: 3rem;}}
h1, h2, h3 {{ color: #f4f7ff; }}
.hero {{
  padding: 1.25rem 0 1.5rem 0;
}}
.eyebrow {{
  color: {MINT}; font-size: .75rem; font-weight: 800; letter-spacing: 2px;
}}
.panel {{
  background: rgba(18,35,68,.92); border: 1px solid #2b4168;
  border-radius: 20px; padding: 1.25rem;
}}
.note {{ color: {MUTED}; font-size: .92rem; line-height: 1.55; }}
div[data-testid="stTextArea"] textarea, div[data-testid="stSelectbox"] {{
  background: #09162e;
}}
.stButton button[kind="primary"] {{
  background: {MINT}; color: #07172b; border: 0; font-weight: 800;
}}
</style>
""", unsafe_allow_html=True)

SCENARIOS = {
    "Refund QR-code trick": "A caller says I must scan a QR code and enter my UPI PIN to receive a refund.",
    "OTP phishing": "A caller says my account will be blocked unless I share an OTP.",
    "Accidental payment": "A stranger says they sent money by mistake and wants me to return it to another number.",
    "Unknown collect request": "I got a collect request from an unknown person asking me to approve and enter my UPI PIN.",
    "Fake payment screenshot": "A buyer shows a screenshot saying they paid, but I cannot see the money in my app.",
    "Unknown APK prize app": "A message says I won a prize and asks me to install an APK from a link.",
    "Urgent KYC link": "A text says my bank KYC expires today and asks me to sign in through a link.",
    "Screen-sharing request": "A support caller asks me to install a screen-sharing app to fix a UPI problem.",
    "Payment to receive money": "Someone says I must pay a small fee first to receive a scholarship or prize.",
    "Look-alike UPI handle": "A shop's payment QR or UPI ID looks slightly different from the one the shop gave me.",
    "Fake customer-care number": "A search result gives a customer-care number and the caller asks for my PIN.",
    "Unexpected PIN prompt": "A payment app asks for my UPI PIN after I clicked a link I did not trust.",
    "Fake delivery fee": "A text about a parcel I did not order asks me to pay a tiny fee through a link.",
    "Impersonation of a relative": "Someone using my relative's profile urgently asks for money to a new UPI ID.",
    "Unexpected payment received": "My app shows an unexpected incoming payment and a stranger calls asking me to send it back immediately.",
}

SYSTEM_INSTRUCTIONS = """
You are UPI Safety Coach, an educational digital-payment safety assistant for students and families in India.
Review a user's description of a possible UPI scam. Give practical, cautious, plain-language guidance.
Return a helpful answer with these sections:
1. Risk level: HIGH RISK, CAUTION, or NEEDS A CLOSER CHECK.
2. Why it may be risky: list concrete warning signs in the user's description.
3. Safer next steps: short numbered actions.
4. If money or account access may already be affected: recommend contacting the bank/payment app through its official app/site or the number printed on the bank card, and reporting suspected cyber financial fraud in India via 1930 and cybercrime.gov.in. Encourage a trusted adult's help for a student.
Important rules:
- Never ask for a UPI PIN, OTP, password, full account number, card details, or private identity data.
- Remind users not to paste such secrets into the app. If a message contains them, tell the user to remove them and do not repeat them.
- Do not claim you can inspect bank accounts or verify transactions.
- Do not guarantee that something is safe or fraudulent. State that this is guidance, not a certified fraud detector.
- Be calm, non-judgmental, and easy to understand.
- If the situation is unclear, say what needs independent verification and advise not to approve/send money until verified.
"""

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")

def ollama_is_running():
    try:
        r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=2)
        return r.ok
    except requests.RequestException:
        return False

st.markdown('<div class="eyebrow">PAUSE · CHECK · PAY SAFELY</div>', unsafe_allow_html=True)
st.title("🛡️ UPI Safety Coach AI")
st.markdown(
    '<div class="hero"><h3>Think before you tap. <span style="color:#56e0c0">Spot the scam.</span></h3>'
    '<p class="note">Describe a suspicious payment message or situation. AI will explain possible warning signs and safer next steps.</p></div>',
    unsafe_allow_html=True
)

ollama_running = ollama_is_running()
if ollama_running:
    st.success(f"Local AI service found. Model selected: {OLLAMA_MODEL}. Do not enter private financial information.")
else:
    st.warning("Local AI is not running yet. Install Ollama, download the model, and start Ollama using the README steps. No paid API key is needed.")

left, right = st.columns([1.15, .85], gap="large")

with left:
    st.markdown('<div class="panel">', unsafe_allow_html=True)
    st.subheader("🔎 Check a suspicious situation")
    st.caption("Do not enter real bank details, UPI PINs, OTPs, passwords, phone numbers, or account information.")
    st.info("New: risk indicator, safety checklist, and downloadable report. The risk indicator is an estimate, not a certified fraud detector.")
    selected = st.selectbox("Try a sample scenario", ["Choose a sample…"] + list(SCENARIOS.keys()))
    initial_text = SCENARIOS.get(selected, "")
    story = st.text_area(
        "What happened?",
        value=initial_text,
        height=170,
        placeholder="Example: Someone called saying they are from my bank and asked for my UPI PIN to reverse a payment…",
    )
    analyze = st.button("Analyze with AI →", type="primary", use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

    if analyze:
        clean_story = story.strip()
        if not clean_story:
            st.info("Choose a sample or describe the situation first.")
        elif len(clean_story) > 5000:
            st.error("Please shorten the description to 5,000 characters or fewer.")
        elif not ollama_running:
            st.error("Local AI is not running. Start Ollama and make sure the selected model is downloaded, then try again.")
        else:
            with st.spinner("Checking for warning signs…"):
                try:
                    response = requests.post(
                        f"{OLLAMA_URL}/api/chat",
                        json={
                            "model": OLLAMA_MODEL,
                            "messages": [
                                {"role": "system", "content": SYSTEM_INSTRUCTIONS},
                                {"role": "user", "content": clean_story},
                            ],
                            "stream": False,
                        },
                        timeout=180,
                    )
                    response.raise_for_status()
                    answer = response.json().get("message", {}).get("content", "").strip()
                    if not answer:
                        raise ValueError("The local model returned an empty response.")
                    # Simple transparent heuristic score to complement—not replace—the AI answer.
                    lower_story = clean_story.lower()
                    high_signals = ["otp", "upi pin", "pin to receive", "scan a qr", "screen-sharing", "install an apk", "pay a fee", "urgent", "account will be blocked", "not appear", "screenshot"]
                    hits = [term for term in high_signals if term in lower_story]
                    risk_score = min(95, 15 + len(hits) * 13)
                    if any(term in lower_story for term in ["upi pin", "otp", "scan a qr", "install an apk", "screen-sharing", "pay a fee"]):
                        risk_label = "HIGH CAUTION"
                    elif hits:
                        risk_label = "CAUTION"
                    else:
                        risk_label = "NEEDS VERIFICATION"
                    st.markdown('<div class="panel">', unsafe_allow_html=True)
                    st.subheader("AI safety assessment")
                    st.metric("Estimated warning level", risk_label, f"Indicator: {risk_score}/100")
                    st.progress(risk_score / 100)
                    st.caption("This simple indicator is based on words in the description. It is not a validated fraud score and may be wrong.")
                    st.markdown(answer)
                    st.markdown("#### Safety checklist")
                    st.markdown("\n".join(["- [ ] Verify the transaction in your official bank/UPI app.", "- [ ] Do not share your PIN, OTP, or password.", "- [ ] Do not approve a collect request you do not understand.", "- [ ] If pressured, pause and contact the bank using official contact details."]))
                    st.caption("AI guidance can be wrong. Verify independently through official channels.")
                    report = f"UPI Safety Coach — Analysis Report\nCreated: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\nSituation entered:\n{clean_story}\n\nEstimated warning level: {risk_label} (indicator {risk_score}/100)\n\nAI assessment:\n{answer}\n\nNote: Educational guidance only; not a certified fraud detector. Verify through official channels."
                    st.download_button("Download analysis report (.txt)", data=report, file_name="upi_safety_analysis_report.txt", mime="text/plain")
                    st.markdown('</div>', unsafe_allow_html=True)
                except requests.exceptions.ConnectionError:
                    st.error("Could not reach Ollama. Open the Ollama app and try again.")
                except requests.exceptions.Timeout:
                    st.error("The local model took too long to respond. Try a shorter description or a smaller model.")
                except Exception as e:
                    st.error("The local AI request failed. Check that the model is downloaded and Ollama is running.")
                    st.caption(f"Technical detail: {type(e).__name__}: {e}")

with right:
    st.markdown('<div class="panel">', unsafe_allow_html=True)
    st.subheader("How it works")
    st.markdown("""
**1 · Describe**  
Choose a sample or write what happened.

**2 · Analyze**  
The app sends your description to the local AI model on this computer.

**3 · Get guidance**  
AI explains warning signs and safer actions.

**4 · Save a report**  
Download the analysis as a text file. The app does not send a report to police or a bank.
""")
    st.markdown("---")
    st.subheader("Remember")
    st.markdown("""
- Never share your UPI PIN or OTP.
- You do not enter a UPI PIN to receive money.
- Verify requests in your official UPI/bank app.
- Do not install unknown apps from message links.
- If unsure, stop and ask a trusted adult or your bank.
""")
    st.markdown('</div>', unsafe_allow_html=True)

st.markdown("---")
a, b = st.columns(2, gap="large")
with a:
    st.markdown('<div class="panel">', unsafe_allow_html=True)
    st.subheader("🆘 If money may have been lost")
    st.markdown("""
1. Contact your bank or UPI app using its official app/site.
2. In India, report suspected cyber financial fraud promptly by calling **1930** and visiting **cybercrime.gov.in**.
3. Save transaction references and screenshots. Never share PINs or OTPs with someone claiming to help.
""")
    st.markdown('</div>', unsafe_allow_html=True)
with b:
    st.markdown('<div class="panel">', unsafe_allow_html=True)
    st.subheader("Privacy and limitations")
    st.markdown("""
This is a learning tool, not a bank service or certified fraud detector. It cannot see your transactions or confirm whether a payment is genuine. The description is processed by the local model on your computer. Do not enter personal or financial secrets.
""")
    st.markdown('</div>', unsafe_allow_html=True)

st.caption("Student prototype · AI-assisted awareness only · Always verify through official channels. The report button only downloads a file; it does not submit an official complaint.")
