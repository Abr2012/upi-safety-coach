import io
import os
import streamlit as st

st.set_page_config(page_title="UPI Safety Coach", page_icon="🛡️", layout="centered")

# ---------- Config ----------
LANGUAGES = {
    "English": "en",
    "Hindi": "hi",
    "Hinglish (mixed)": "hi-en",
    "Marathi": "mr",
    "Tamil": "ta",
    "Telugu": "te",
    "Bengali": "bn",
    "Kannada": "kn",
    "Gujarati": "gu",
    "Punjabi": "pa",
}

# ---------- STT backends ----------
@st.cache_resource
def _openai_client():
    from openai import OpenAI
    return OpenAI(api_key=os.environ["OPENAI_API_KEY"])

def _transcribe_openai(audio_bytes: bytes, lang_code: str) -> str:
    buf = io.BytesIO(audio_bytes)
    buf.name = "audio.wav"
    model = os.getenv("STT_MODEL", "gpt-4o-mini-transcribe")
    kwargs = {"model": model, "file": buf}
    if lang_code and lang_code != "hi-en":
        kwargs["language"] = lang_code.split("-")[0]
    resp = _openai_client().audio.transcriptions.create(**kwargs)
    return (resp.text or "").strip()

def _transcribe_sarvam(audio_bytes: bytes, lang_code: str) -> str:
    import requests
    api_key = os.environ["SARVAM_API_KEY"]
    if lang_code == "hi-en":
        sarvam_lang = "hi-IN"
    else:
        sarvam_lang = f"{lang_code}-IN"
    r = requests.post(
        "https://api.sarvam.ai/speech-to-text",
        headers={"api-subscription-key": api_key},
        files={"file": ("audio.wav", audio_bytes, "audio/wav")},
        data={"model": "saarika:v2", "language_code": sarvam_lang},
        timeout=60,
    )
    r.raise_for_status()
    return (r.json().get("transcript") or "").strip()

def transcribe(audio_bytes: bytes, lang_code: str, provider: str) -> str:
    if provider == "Sarvam":
        return _transcribe_sarvam(audio_bytes, lang_code)
    return _transcribe_openai(audio_bytes, lang_code)

# ---------- YOUR COACH LOGIC (replace this) ----------
def coach_reply(user_text: str, language: str) -> str:
    """
    Replace this with your existing UPI-safety logic
    (LLM call, rules, scam classifier, whatever you have).
    """
    return f"_(stub)_ You said: **{user_text}**"

# ---------- UI ----------
st.title("🛡️ UPI Safety Coach")
st.caption("Describe a suspicious payment or scam attempt — by voice or text.")

with st.sidebar:
    st.header("Settings")
    language = st.selectbox("Language", list(LANGUAGES.keys()), index=0)
    provider = st.selectbox("Speech engine", ["OpenAI", "Sarvam"], index=0)
    st.caption("Sarvam handles Indian languages & Hinglish better. OpenAI is a solid default.")

tab_voice, tab_text = st.tabs(["🎙️ Voice", "⌨️ Text"])

with tab_voice:
    st.write("Tap the mic, describe your situation, then stop.")
    audio = st.audio_input("Record", key="voice_input")

    if audio is not None:
        with st.spinner("Transcribing…"):
            try:
                transcript = transcribe(audio.getvalue(), LANGUAGES[language], provider)
            except Exception as e:
                st.error(f"Transcription failed: {e}")
                transcript = ""

        if transcript:
            st.success("Here's what I heard:")
            edited = st.text_area("Confirm or edit before continuing", transcript, height=100)
            if st.button("Get advice", key="voice_submit"):
                st.markdown(coach_reply(edited, language))
        else:
            st.warning("No speech detected. Try again, or use the Text tab.")

with tab_text:
    text = st.text_area("Describe your situation", height=120)
    if st.button("Get advice", key="text_submit") and text.strip():
        st.markdown(coach_reply(text, language))









