import os
import re
from datetime import datetime
from urllib.parse import urlparse

import requests
import streamlit as st

st.set_page_config(
    page_title="UPI Safety Coach AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------- Configuration ----------
def get_setting(name: str, default: str = "") -> str:
    """Read a setting from environment variables first, then Streamlit secrets."""
    value = os.getenv(name)
    if value:
        return value
    try:
        return str(st.secrets.get(name, default))
    except Exception:
        return default


OLLAMA_URL = get_setting("OLLAMA_URL", "http://localhost:8080").rstrip("/")
OLLAMA_MODEL = get_setting("OLLAMA_MODEL", "llama3.2:3b")
BRIDGE_TOKEN = get_setting("BRIDGE_TOKEN", "")
REQUEST_TIMEOUT = int(get_setting("AI_TIMEOUT_SECONDS", "180"))

# ---------- Safety content ----------
SCENARIOS = {
    "Fake refund QR code": "A caller says I must scan a QR code and enter my UPI PIN to receive a refund.",
    "OTP phishing": "A caller says my bank account will be blocked unless I share an OTP.",
    "Fake payment screenshot": "A buyer shows a payment screenshot, but the money is not visible in my official payment app.",
    "Unknown collect request": "I received a collect request from an unknown person asking me to approve it.",
    "Urgent KYC message": "A text says my bank KYC expires today and asks me to log in through a link.",
    "Screen-sharing request": "A support caller asks me to install a screen-sharing app to fix a UPI problem.",
    "Accidental payment pressure": "A stranger says they sent money by mistake and wants me to return it to a different UPI ID.",
    "Prize fee": "A message says I won a prize but must pay a fee first to receive it.",
}

SYSTEM_INSTRUCTIONS = """
You are UPI Safety Coach, an educational digital-payment safety assistant for people in India.
Analyze any scenario the user describes, not only sample cases. Reply in the language selected by
the user. Use plain, respectful, concise language and this structure:
1. Risk level: HIGH RISK, CAUTION, or NEEDS A CLOSER CHECK.
2. Why it may be risky: evidence from the user's description; separate facts from assumptions.
3. Safe next steps: numbered, practical actions.
4. What to verify: use the official bank/payment app or official contact details independently.
5. If money may have been lost: contact the bank/payment provider promptly. In India, suspected
   cyber financial fraud can be reported at 1930 and cybercrime.gov.in.
Rules:
- Never ask for, repeat, or expose a PIN, OTP, password, full account/card details, or private ID.
  If such details appear in the input, warn the user not to share them and do not quote them back.
- Never tell users to approve an unfamiliar collect request or send money as a test.
- A UPI PIN authorizes a payment; it is not required to receive money.
- Never claim to inspect accounts, verify transactions, identify a caller, or confirm a QR code/link.
- Do not guarantee a situation is safe or definitely fraudulent. State uncertainty and missing evidence.
- Do not invent bank policies, official phone numbers, or links.
- If the user is a student/minor, suggest involving a trusted adult when appropriate.
- This is educational guidance, not a certified fraud detector.
"""

LANGUAGES = {
    "English": "English",
    "മലയാളം (Malayalam)": "Malayalam",
    "தமிழ் (Tamil)": "Tamil",
    "हिन्दी (Hindi)": "Hindi",
}

# ---------- Session state ----------
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []
if "last_analysis" not in st.session_state:
    st.session_state.last_analysis = None
if "quiz_score" not in st.session_state:
    st.session_state.quiz_score = 0
if "quiz_answered" not in st.session_state:
    st.session_state.quiz_answered = set()

# ---------- Styling ----------
st.markdown("""
<style>
:root { color-scheme: dark; }
.stApp {
  background: radial-gradient(circle at 85% 0%, #1b3b69 0%, #0a1428 48%, #08101e 100%);
  color: #f4f7ff;
}
.block-container { max-width: 1180px; padding-top: 1.7rem; padding-bottom: 3rem; }
h1, h2, h3 { color: #f4f7ff; }
[data-testid="stMetric"] {
  background: rgba(22, 42, 76, .72); border: 1px solid #2c456c;
  border-radius: 16px; padding: 14px;
}
.stButton button[kind="primary"] {
  background: #56e0c0; color: #07172b; border: 0; font-weight: 800;
}
div[data-testid="stTextArea"] textarea { border-radius: 12px; }
.coach-card {
  background: rgba(18, 35, 65, .88); border: 1px solid #2b4168;
  border-radius: 18px; padding: 1.15rem 1.25rem; margin-bottom: .8rem;
}
.muted { color: #b3c1da; font-size: .92rem; }
</style>
""", unsafe_allow_html=True)

# ---------- Helpers ----------
def make_headers():
    headers = {"Content-Type": "application/json"}
    if BRIDGE_TOKEN:
        headers["Authorization"] = f"Bearer {BRIDGE_TOKEN}"
    return headers


def ask_ai(prompt: str, language: str, include_history: bool = True) -> str:
    """Send the user's scenario to the configured Ollama-compatible bridge."""
    messages = [{"role": "system", "content": SYSTEM_INSTRUCTIONS}]
    if include_history:
        # Send only the latest few turns to keep requests bounded.
        for item in st.session_state.chat_history[-6:]:
            messages.append({"role": item["role"], "content": item["content"]})
    messages.append({
        "role": "user",
        "content": f"Answer in {language}. Analyze this scenario or question:\n\n{prompt}",
    })
    response = requests.post(
        f"{OLLAMA_URL}/api/chat",
        headers=make_headers(),
        json={
            "model": OLLAMA_MODEL,
            "messages": messages,
            "stream": False,
            "options": {"temperature": 0.2},
        },
        timeout=REQUEST_TIMEOUT,
    )
    if response.status_code == 401:
        raise PermissionError(
            "The AI bridge returned 401 Unauthorized. Check that BRIDGE_TOKEN in Streamlit "
            "Secrets matches the token used to start bridge.py. Do not share the token."
        )
    response.raise_for_status()
    payload = response.json()
    answer = payload.get("message", {}).get("content", "").strip()
    if not answer:
        raise ValueError("The AI returned an empty answer.")
    return answer


def safe_url_findings(text: str):
    """Inspect URL text locally only. This function never opens or fetches a URL."""
    candidates = re.findall(r"(?:https?://|www\.)[^\s<>\]\)\"']+", text, flags=re.I)
    findings = []
    suspicious_terms = ("verify", "kyc", "refund", "reward", "claim", "login", "secure", "bank")
    for raw in candidates:
        cleaned = raw.rstrip(".,!?;:")
        normalized = cleaned if cleaned.lower().startswith(("http://", "https://")) else "https://" + cleaned
        parsed = urlparse(normalized)
        host = (parsed.hostname or "").lower()
        flags = []
        if parsed.scheme == "http":
            flags.append("uses unencrypted HTTP")
        if host.startswith("xn--") or ".xn--" in host:
            flags.append("contains an internationalized/punycode hostname")
        if host and re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
            flags.append("uses an IP address instead of a familiar domain")
        if "@" in parsed.netloc:
            flags.append("contains an @ sign in the address")
        if host.count("-") >= 3:
            flags.append("has several hyphens in the hostname")
        if any(term in (parsed.path + "?" + parsed.query).lower() for term in suspicious_terms):
            flags.append("path/query uses account, verification, refund, or reward wording")
        findings.append({"url": cleaned, "host": host, "flags": flags})
    return findings


def show_request_error(exc: Exception):
    if isinstance(exc, PermissionError):
        st.error(str(exc))
    elif isinstance(exc, requests.exceptions.Timeout):
        st.error("The AI took too long to respond. Try a shorter message or check that the model is running.")
    elif isinstance(exc, requests.exceptions.ConnectionError):
        st.error(
            "Could not connect to the AI bridge. Check Ollama, bridge.py, the current tunnel URL, "
            "and Streamlit Secrets. A temporary Cloudflare tunnel works only while its process is running."
        )
    elif isinstance(exc, requests.exceptions.HTTPError):
        status = exc.response.status_code if exc.response is not None else "unknown"
        st.error(f"The AI service returned HTTP {status}. Check bridge logs and configuration.")
    else:
        st.error(f"The AI response could not be processed ({type(exc).__name__}). Please try again.")


def reset_history():
    st.session_state.chat_history = []
    st.session_state.last_analysis = None


# ---------- Header / sidebar ----------
st.markdown('<p style="color:#56e0c0;font-weight:800;letter-spacing:2px;">PAUSE · CHECK · PAY SAFELY</p>', unsafe_allow_html=True)
st.title("🛡️ UPI Safety Coach AI")
st.markdown(
    '<p class="muted">Ask about any payment situation, suspicious message, or UPI question. '
    'Get practical guidance without needing a predefined scenario.</p>',
    unsafe_allow_html=True,
)

with st.sidebar:
    st.header("⚙️ Settings")
    language_label = st.selectbox("Response language", list(LANGUAGES.keys()), index=0)
    language = LANGUAGES[language_label]
    st.caption(f"AI model: `{OLLAMA_MODEL}`")
    st.caption("Connection is checked when you submit a question.")
    if st.button("Clear session history", use_container_width=True):
        reset_history()
        st.rerun()
    st.markdown("---")
    st.markdown("**Privacy reminder**")
    st.caption("Do not paste PINs, OTPs, passwords, full account/card numbers, or personal identity details.")
    st.markdown("[Cybercrime reporting portal](https://cybercrime.gov.in)")

tab_ask, tab_url, tab_quiz, tab_history = st.tabs([
    "💬 Ask AI", "🔗 Message / URL checker", "🎯 Safety quiz", "🕘 Session history"
])

# ---------- Ask anything ----------
with tab_ask:
    st.markdown('<div class="coach-card">', unsafe_allow_html=True)
    st.subheader("Describe any situation")
    st.caption("Choose an optional example, or type your own situation or follow-up question.")
    sample_name = st.selectbox("Optional: load a sample", ["Write my own situation…"] + list(SCENARIOS.keys()))
    if "scenario_text" not in st.session_state:
        st.session_state.scenario_text = ""
    if sample_name != st.session_state.get("last_sample_name", "Write my own situation…"):
        st.session_state.scenario_text = SCENARIOS.get(sample_name, "")
        st.session_state.last_sample_name = sample_name
    scenario = st.text_area(
        "What happened?",
        key="scenario_text",
        height=165,
        max_chars=5000,
        placeholder="Example: Someone says they sent money by mistake and pressures me to return it to another UPI ID. What should I do?",
    )
    analyze = st.button("Analyze with AI →", type="primary", use_container_width=True)
    st.markdown("</div>", unsafe_allow_html=True)

    if analyze:
        clean = scenario.strip()
        if not clean:
            st.warning("Please type a situation or question first.")
        else:
            with st.spinner("Analyzing warning signs and safer next steps…"):
                try:
                    answer = ask_ai(clean, language, include_history=True)
                    st.session_state.chat_history.extend([
                        {"role": "user", "content": clean},
                        {"role": "assistant", "content": answer},
                    ])
                    st.session_state.last_analysis = {
                        "question": clean,
                        "answer": answer,
                        "language": language,
                        "created": datetime.now().strftime("%Y-%m-%d %H:%M"),
                    }
                    st.success("Analysis ready")
                except Exception as exc:
                    show_request_error(exc)

    if st.session_state.last_analysis:
        item = st.session_state.last_analysis
        st.markdown('<div class="coach-card">', unsafe_allow_html=True)
        st.subheader("Your AI safety assessment")
        st.caption(f"Language: {item['language']} · {item['created']}")
        st.markdown(item["answer"])
        st.markdown("---")
        st.markdown("**Quick checklist**")
        st.markdown("""
- [ ] Check payment status in the official payment/bank app.
- [ ] Never share your UPI PIN, OTP, or password.
- [ ] Do not approve a collect request you do not understand.
- [ ] Avoid opening suspicious links or installing unknown apps.
- [ ] Pause and independently verify if someone pressures you.
""")
        report_text = (
            "UPI Safety Coach AI — Educational Report\n"
            f"Created: {item['created']}\nLanguage: {item['language']}\n\n"
            "Situation:\n" + item["question"] + "\n\n"
            "AI assessment:\n" + item["answer"] + "\n\n"
            "Limitations: AI-generated educational guidance, not a verified fraud finding. "
            "Verify through official channels. Remove private details before sharing."
        )
        st.download_button(
            "⬇️ Download this analysis (.txt)",
            data=report_text,
            file_name="upi_safety_report.txt",
            mime="text/plain",
        )
        st.caption("Before sharing a report, check it for personal details.")
        st.markdown("</div>", unsafe_allow_html=True)

# ---------- Message and URL checker ----------
with tab_url:
    st.subheader("Check suspicious message text")
    st.caption("Paste the message or URL text. The app does not open links or verify a website's ownership.")
    suspicious_text = st.text_area(
        "Message or URL to inspect",
        height=140,
        max_chars=5000,
        placeholder="Example: Your bank KYC expires today. Click this link to avoid account suspension…",
        key="suspicious_text",
    )
    check_cols = st.columns(2)
    with check_cols[0]:
        inspect_url = st.button("Check URL clues", use_container_width=True)
    with check_cols[1]:
        analyze_message = st.button("Analyze message with AI", type="primary", use_container_width=True)

    if inspect_url:
        if not suspicious_text.strip():
            st.info("Paste a message or URL first.")
        else:
            found = safe_url_findings(suspicious_text)
            if not found:
                st.info("No obvious URL was detected. A message can still be suspicious without a link.")
            else:
                for entry in found:
                    st.markdown(f"**Address text:** `{entry['url']}`")
                    st.write(f"Hostname: `{entry['host'] or 'not detected'}`")
                    if entry["flags"]:
                        for flag in entry["flags"]:
                            st.warning(flag.capitalize() + ".")
                    else:
                        st.info("No simple URL warning pattern detected. This does not mean the URL is safe.")
            st.caption("These are simple text-based clues, not a reputation lookup or a guarantee.")
    if analyze_message:
        if not suspicious_text.strip():
            st.info("Paste a message first.")
        else:
            with st.spinner("Reviewing the message…"):
                try:
                    answer = ask_ai(
                        "Review this message for possible payment or phishing warning signs. Do not open any links. "
                        "Explain uncertainty and give safe next steps:\n\n" + suspicious_text.strip(),
                        language,
                        include_history=False,
                    )
                    st.markdown('<div class="coach-card">', unsafe_allow_html=True)
                    st.subheader("Message assessment")
                    st.markdown(answer)
                    st.markdown("</div>", unsafe_allow_html=True)
                except Exception as exc:
                    show_request_error(exc)

# ---------- Quiz ----------
QUIZ = [
    {
        "q": "A caller says you must enter your UPI PIN to receive a refund. What should you do?",
        "options": [
            "Enter the PIN because refunds require it",
            "Pause and verify through the official app; do not enter the PIN",
            "Share an OTP instead",
            "Scan the code and follow every instruction",
        ],
        "answer": 1,
        "why": "A UPI PIN authorizes a payment; it is not needed just to receive money.",
    },
    {
        "q": "A buyer shows a payment screenshot, but your official app shows no incoming payment. What is safest?",
        "options": [
            "Trust the screenshot",
            "Hand over the item immediately",
            "Verify the actual transaction in your official app or bank account",
            "Ask the buyer for their UPI PIN",
        ],
        "answer": 2,
        "why": "Screenshots can be edited or payments can fail. Verify the actual account transaction.",
    },
    {
        "q": "An unknown person sends a collect request. What should you do?",
        "options": [
            "Approve it to see what happens",
            "Enter your PIN if the amount looks small",
            "Forward the request to friends",
            "Do not approve it unless you independently understand and expect it",
        ],
        "answer": 3,
        "why": "Approving an unexpected collect request may authorize a payment.",
    },
    {
        "q": "Someone claiming to be bank support asks for your OTP over the phone. What is the safe response?",
        "options": [
            "Do not share it; contact the bank through official channels",
            "Share it if they know your name",
            "Send the OTP in a chat",
            "Share it only after they hurry you",
        ],
        "answer": 0,
        "why": "Do not share OTPs with callers. Independently contact the bank using official details.",
    },
    {
        "q": "You clicked a suspicious payment link but have not entered any details. What should you do next?",
        "options": [
            "Enter details to see if the site works",
            "Forward the link to others to test it",
            "Close it, do not enter information, and verify through official channels",
            "Install any app it recommends",
        ],
        "answer": 2,
        "why": "Do not provide information or install software from a suspicious link; verify independently.",
    },
]

with tab_quiz:
    st.subheader("Practice spotting payment scams")
    st.caption("Choose an answer for each question, then check your score. This is a learning activity.")
    for i, question in enumerate(QUIZ):
        st.markdown(f'<div class="coach-card"><strong>Question {i+1} of {len(QUIZ)}</strong><br>{question["q"]}</div>', unsafe_allow_html=True)
        choice = st.radio(
            f"Your answer for question {i+1}",
            question["options"],
            key=f"quiz_choice_{i}",
            label_visibility="collapsed",
        )
        if st.button(f"Check answer {i+1}", key=f"quiz_check_{i}"):
            st.session_state.quiz_answered.add(i)
            if question["options"].index(choice) == question["answer"]:
                st.session_state[f"quiz_result_{i}"] = True
            else:
                st.session_state[f"quiz_result_{i}"] = False
        if i in st.session_state.quiz_answered:
            if st.session_state.get(f"quiz_result_{i}", False):
                st.success("Good choice! " + question["why"])
            else:
                st.warning("Review this: " + question["why"])
    if st.session_state.quiz_answered:
        score = sum(1 for i in st.session_state.quiz_answered if st.session_state.get(f"quiz_result_{i}", False))
        st.metric("Answered correctly", f"{score} / {len(st.session_state.quiz_answered)}")
    if st.button("Reset quiz"):
        for i in range(len(QUIZ)):
            st.session_state.quiz_answered.discard(i)
            st.session_state.pop(f"quiz_result_{i}", None)
            st.session_state.pop(f"quiz_choice_{i}", None)
        st.rerun()

# ---------- Session history ----------
with tab_history:
    st.subheader("Conversation history for this session")
    st.caption("This history is kept only in the current Streamlit session. It is not a permanent database.")
    if not st.session_state.chat_history:
        st.info("Your questions and AI answers will appear here after you analyze a scenario.")
    else:
        for index, item in enumerate(st.session_state.chat_history):
            label = "You" if item["role"] == "user" else "UPI Safety Coach AI"
            with st.expander(f"{label} · message {index + 1}", expanded=False):
                st.markdown(item["content"])
        transcript = "\n\n".join(
            ("YOU" if item["role"] == "user" else "UPI SAFETY COACH AI") + ":\n" + item["content"]
            for item in st.session_state.chat_history
        )
        st.download_button(
            "Download session transcript (.txt)",
            data=transcript,
            file_name="upi_safety_session.txt",
            mime="text/plain",
        )

# ---------- Emergency / footer ----------
st.markdown("---")
col_a, col_b = st.columns(2, gap="large")
with col_a:
    st.markdown('<div class="coach-card">', unsafe_allow_html=True)
    st.subheader("🆘 If money may have been lost")
    st.markdown("""
1. Contact your bank/payment provider through its official app or website.
2. In India, report suspected cyber financial fraud promptly at **1930** and **[cybercrime.gov.in](https://cybercrime.gov.in)**.
3. Keep transaction references and evidence; never share PINs or OTPs with someone claiming to help.
""")
    st.markdown("</div>", unsafe_allow_html=True)
with col_b:
    st.markdown('<div class="coach-card">', unsafe_allow_html=True)
    st.subheader("🔐 Privacy and limitations")
    st.markdown("""
This is an educational prototype, not a bank service or certified fraud detector. It cannot see your bank transactions, verify a payment, or guarantee that a link is safe. URL checks use simple local text patterns only. Do not paste secrets or personal financial details.
""")
    st.markdown("</div>", unsafe_allow_html=True)

st.caption("UPI Safety Coach AI · Student prototype · Verify important decisions through official channels.")






