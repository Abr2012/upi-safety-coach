import os
from datetime import datetime

import requests
import streamlit as st

st.set_page_config(page_title="UPI Safety Coach AI", page_icon="🛡️", layout="wide")

NAVY = "#0b1730"
MINT = "#56e0c0"
MUTED = "#a9b8d5"

st.markdown(f"""
<style>
.stApp {{background: radial-gradient(circle at 80% 0%, #193663 0%, {NAVY} 48%); color:#f4f7ff;}}
.block-container {{max-width:1120px;padding-top:2rem;padding-bottom:3rem;}}
h1,h2,h3 {{color:#f4f7ff;}}
.note {{color:{MUTED};font-size:.92rem;line-height:1.55;}}
.panel {{background:rgba(18,35,68,.92);border:1px solid #2b4168;border-radius:20px;padding:1.25rem;}}
.stButton button[kind="primary"] {{background:{MINT};color:#07172b;border:0;font-weight:800;}}
</style>
""", unsafe_allow_html=True)

SCENARIOS = {
    "Refund QR-code trick": "A caller says I must scan a QR code and enter my UPI PIN to receive a refund.",
    "OTP phishing": "A caller says my account will be blocked unless I share an OTP.",
    "Accidental payment": "A stranger says they sent money by mistake and wants me to return it to another number.",
    "Unknown collect request": "I got a collect request from an unknown person asking me to approve it and enter my UPI PIN.",
    "Fake payment screenshot": "A buyer shows a screenshot saying they paid, but I cannot see the money in my official payment app.",
    "Unknown APK prize app": "A message says I won a prize and asks me to install an app from a link.",
    "Urgent KYC link": "A text says my bank KYC expires today and asks me to sign in through a link.",
    "Screen-sharing request": "A support caller asks me to install a screen-sharing app to fix a UPI problem.",
    "Payment to receive money": "Someone says I must pay a fee first to receive a scholarship or prize.",
    "Look-alike UPI handle": "A shop's payment QR or UPI ID looks slightly different from the one the shop gave me.",
    "Fake customer-care number": "A search result gives a customer-care number and the caller asks for my PIN.",
    "Unexpected PIN prompt": "A payment app asks for my UPI PIN after I clicked a link I do not trust.",
    "Fake delivery fee": "A text about a parcel I did not order asks me to pay a small fee through a link.",
    "Impersonation of a relative": "Someone using my relative's profile urgently asks for money to a new UPI ID.",
    "Unexpected payment received": "My app shows an unexpected incoming payment and a stranger calls asking me to send it back immediately.",
}

SYSTEM_INSTRUCTIONS = """
You are UPI Safety Coach, an educational digital-payment safety assistant for people in India.
Analyze ANY situation the user describes, not just predefined examples. It may be a UPI scenario,
bank message, QR code, collect request, payment dispute, suspicious call, online shopping request,
or a general question. If it is not about UPI or digital-payment safety, say so briefly and still
answer any relevant general safety question within your scope.

Use plain, calm, non-judgmental language. Organize the answer under:
1. Risk level: HIGH RISK, CAUTION, or NEEDS A CLOSER CHECK.
2. What stands out: concrete evidence from the description; distinguish facts from assumptions.
3. What to do now: clear, numbered actions.
4. What to verify independently: only through the official bank/payment app/site or contact details
   printed on a bank card; never rely on a number or link sent by a suspicious caller/message.
5. If money or account access may already be affected: contact the bank/payment provider urgently.
   In India, suspected cyber financial fraud can be reported at 1930 and cybercrime.gov.in.
   Encourage a student to get help from a trusted adult.

Safety rules:
- Never request or repeat UPI PINs, OTPs, passwords, full account/card details, or private identity data.
- If the user included secrets, do not quote them back; tell them to remove them from the message.
- Never ask the user to approve a collect request or send money as a test.
- Never claim you can inspect a bank account, verify a transaction, identify a person, or confirm a QR code.
- Do not guarantee something is safe or fraudulent. Explain uncertainty and what evidence is missing.
- Do not invent facts, bank policies, links, or phone numbers.
- A UPI PIN is used to authorize sending money, not to receive money.
- This is educational guidance, not a certified fraud detector. If unsure, advise pausing before
  sending/approving money and verifying through official channels.
"""

def get_setting(name, default=""):
    value = os.getenv(name)
    if value:
        return value
    try:
        return st.secrets[name]
    except Exception:
        return default

OLLAMA_URL = get_setting("OLLAMA_URL", "http://localhost:8080").rstrip("/")
OLLAMA_MODEL = get_setting("OLLAMA_MODEL", "llama3.2:3b")
BRIDGE_TOKEN = get_setting("BRIDGE_TOKEN", "")

def service_is_running():
    try:
        response = requests.get(f"{OLLAMA_URL}/health", timeout=5)
        return response.ok
    except requests.RequestException:
        return False

st.markdown('<p style="color:#56e0c0;font-weight:800;letter-spacing:2px;">PAUSE · CHECK · PAY SAFELY</p>', unsafe_allow_html=True)
st.title("🛡️ UPI Safety Coach AI")
st.markdown('<p class="note">Describe any suspicious payment situation or ask a digital-payment safety question. The AI will explain possible warning signs and safer next steps.</p>', unsafe_allow_html=True)

running = service_is_running()
if running:
    st.success(f"AI service is reachable · Model: {OLLAMA_MODEL}")
else:
    st.warning("The AI service is not reachable right now. Check that Ollama, bridge.py, and (if using a tunnel) cloudflared are running.")

left, right = st.columns([1.15, .85], gap="large")
with left:
    st.markdown('<div class="panel">', unsafe_allow_html=True)
    st.subheader("🔎 Ask about any situation")
    st.caption("Do not enter real UPI PINs, OTPs, passwords, bank details, full phone numbers, or identity information.")
    selected = st.selectbox("Optional: load a sample", ["Write my own situation…"] + list(SCENARIOS.keys()))
    sample = SCENARIOS.get(selected, "")
    if "scenario_text" not in st.session_state:
        st.session_state.scenario_text = sample
    if selected != st.session_state.get("last_selected", "Write my own situation…"):
        if selected == "Write my own situation…":
            st.session_state.scenario_text = ""
        else:
            st.session_state.scenario_text = sample
        st.session_state.last_selected = selected
    story = st.text_area(
        "Describe what happened or ask a question",
        key="scenario_text",
        height=190,
        max_chars=5000,
        placeholder="Example: Someone says they sent me money by mistake and is pressuring me to return it to a different UPI ID. What should I do?",
    )
    analyze = st.button("Analyze with AI →", type="primary", use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

    if analyze:
        clean_story = story.strip()
        if not clean_story:
            st.info("Type a question or describe what happened first.")
        elif not running:
            st.error("The AI service is not reachable. Start Ollama and bridge.py, then retry.")
        else:
            with st.spinner("Thinking through the details and possible warning signs…"):
                try:
                    headers = {"Content-Type": "application/json"}
                    if BRIDGE_TOKEN:
                        headers["Authorization"] = f"Bearer {BRIDGE_TOKEN}"
                    response = requests.post(
                        f"{OLLAMA_URL}/api/chat",
                        headers=headers,
                        json={
                            "model": OLLAMA_MODEL,
                            "messages": [
                                {"role": "system", "content": SYSTEM_INSTRUCTIONS},
                                {"role": "user", "content": clean_story},
                            ],
                            "stream": False,
                            "options": {"temperature": 0.2},
                        },
                        timeout=180,
                    )
                    if response.status_code == 401:
                        st.error("The AI bridge returned 401 Unauthorized. Check that BRIDGE_TOKEN in Streamlit Secrets matches the token used to start bridge.py. Do not share the token in chat.")
                    else:
                        response.raise_for_status()
                        answer = response.json().get("message", {}).get("content", "").strip()
                        if not answer:
                            raise ValueError("The AI returned an empty answer.")
                        st.markdown('<div class="panel">', unsafe_allow_html=True)
                        st.subheader("AI safety assessment")
                        st.markdown(answer)
                        st.markdown("#### Quick safety checklist")
                        st.markdown("""
- [ ] Verify the payment/request inside the official bank or UPI app.
- [ ] Never share your PIN, OTP, or password.
- [ ] Do not approve a collect request you do not understand.
- [ ] Do not install apps or open links sent by suspicious contacts.
- [ ] If pressured, pause and verify through an official channel.
""")
                        st.caption("This is AI-generated educational guidance, not a verified fraud finding.")
                        report = (
                            "UPI Safety Coach — Analysis Report\n"
                            f"Created: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n"
                            "Situation entered:\n[Review your original message for private information before sharing this report.]\n\n"
                            f"AI assessment:\n{answer}\n\n"
                            "Note: Educational guidance only; not a certified fraud detector. "
                            "Verify independently through official channels."
                        )
                        st.download_button("Download analysis report (.txt)", data=report, file_name="upi_safety_analysis_report.txt", mime="text/plain")
                        st.markdown('</div>', unsafe_allow_html=True)
                except requests.exceptions.Timeout:
                    st.error("The AI took too long to respond. Try a shorter description or check whether the local model is still running.")
                except requests.exceptions.ConnectionError:
                    st.error("Could not connect to the AI service. Check Ollama, bridge.py, the tunnel URL, and internet connection.")
                except requests.exceptions.RequestException as exc:
                    st.error(f"The AI request failed ({type(exc).__name__}). Check the bridge logs and try again.")
                except (ValueError, KeyError) as exc:
                    st.error(f"The AI response could not be read ({type(exc).__name__}). Please try again.")

with right:
    st.markdown('<div class="panel">', unsafe_allow_html=True)
    st.subheader("How it works")
    st.markdown("""
**1 · Describe**  
Write your own scenario or use a sample.

**2 · Analyze**  
The app sends the description to your configured local AI service.

**3 · Get guidance**  
AI explains warning signs, uncertainty, and safer actions.

**4 · Save**  
Download a text report if useful.
""")
    st.markdown("---")
    st.subheader("Remember")
    st.markdown("""
- Never share your UPI PIN or OTP.
- You do not enter a UPI PIN to receive money.
- Check payment status in your official app, not a screenshot.
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
1. Contact your bank or UPI app through its official app/site.
2. In India, report suspected cyber financial fraud promptly by calling **1930** and visiting **cybercrime.gov.in**.
3. Keep transaction references and screenshots, but do not share PINs or OTPs with anyone claiming to help.
""")
    st.markdown('</div>', unsafe_allow_html=True)
with b:
    st.markdown('<div class="panel">', unsafe_allow_html=True)
    st.subheader("Privacy and limitations")
    st.markdown("""
This is a learning tool, not a bank service or certified fraud detector. It cannot see your transactions or confirm whether a payment is genuine. Do not enter personal or financial secrets. Check the hosting and AI configuration before using it with real messages.
""")
    st.markdown('</div>', unsafe_allow_html=True)

st.caption("Student prototype · AI-assisted awareness only · Always verify through official channels. The report download does not submit an official complaint.")


