import streamlit as st
from streamlit_mic_recorder import mic_recorder
import openrct2 # Note: Using placeholder or standard openai client in real app, we will use standard openai template
# Let's provide a production-ready, clean app.py using streamlit-mic-recorder and OpenAI Whisper

import os
from openai import OpenAI

st.set_page_config(page_title="UPI Safety AI Coach", page_icon="🔒", layout="centered")

st.title("🔒 Upgraded UPI Safety AI Coach")
st.write("Secure your digital payments with voice-activated safety coaching!")

# Initialize OpenAI Client (Uses streamlit secrets or environment variable)
# To use: add OPENAI_API_KEY in your Streamlit secrets
api_key = st.secrets.get("OPENAI_API_KEY", os.getenv("OPENAI_API_KEY"))

if not api_key:
    st.info("💡 Tip: To enable advanced voice-to-text transcription, add your `OPENAI_API_KEY` to Streamlit Secrets.")

# Session state to hold text input or voice transcription
if "user_input" not in st.session_state:
    st.session_state.user_input = ""

# 🎤 Voice Input Section
st.subheader("🎙️ Voice Command")
st.write("Tap the button below, speak your UPI doubt/scam concern, and click stop.")

# Native recording component
audio = mic_recorder(
    start_prompt="Start Recording 🎤",
    stop_prompt="Stop Recording 🛑",
    key='uploader'
)

if audio:
    st.audio(audio['bytes'], format='audio/wav')
    
    if api_key:
        with st.spinner("Transcribing your voice note with OpenAI Whisper..."):
            try:
                client = OpenAI(api_key=api_key)
                # Save temp file
                with open("temp_audio.wav", "wb") as f:
                    f.write(audio['bytes'])
                
                # Transcribe
                with open("temp_audio.wav", "rb") as audio_file:
                    transcription = client.audio.transcriptions.create(
                        model="whisper-1", 
                        file=audio_file,
                        prompt="UPI, GPay, PhonePe, Paytm, Fraud, Scam, OTP, PIN, Hinglish"
                    )
                st.session_state.user_input = transcription.text
                st.success(f"🗣️ Transcribed: \"{st.session_state.user_input}\"")
                
                # Cleanup
                if os.path.exists("temp_audio.wav"):
                    os.remove("temp_audio.wav")
            except Exception as e:
                st.error(f"Error during audio transcription: {e}")
    else:
        st.warning("⚠️ OpenAI API key is missing. Cannot transcribe audio automatically. Please enter your text query below.")

# 📝 Text Fallback / Refinement
st.subheader("💬 Ask Your UPI Query")
query = st.text_input("Modify your voice transcript or type a query manually:", value=st.session_state.user_input)

# Safety responses database or LLM fallback
if st.button("Get Safety Advice 🚀") or (audio and api_key and st.session_state.user_input):
    active_query = query if query else st.session_state.user_input
    
    if active_query:
        with st.spinner("Analyzing threat levels..."):
            if api_key:
                try:
                    client = OpenAI(api_key=api_key)
                    response = client.chat.completions.create(
                        model="gpt-4o-mini",
                        messages=[
                            {"role": "system", "content": "You are an expert UPI Safety AI Coach. Explain concepts clearly in a mix of Hindi and English (Hinglish) or plain English depending on the user. Provide actionable security steps regarding UPI PINs, fraud links, collect requests, and QR codes. Keep it brief and highly scan-mappable."},
                            {"role": "user", "content": active_query}
                        ]
                    )
                    st.markdown("### 🤖 Coach Response:")
                    st.write(response.choices[0].message.content)
                except Exception as e:
                    st.error(f"LLM Error: {e}")
            else:
                # Fallback rule-based logic
                st.markdown("### 🤖 Coach Response (Rule-Based Fallback):")
                low_query = active_query.lower()
                if "pin" in low_query or "pay" in low_query:
                    st.error("❌ **ALERT:** UPI PIN is strictly for **SENDING** money, never for receiving! If someone asks you to enter your PIN to receive an award or refund, it is a **SCAM**.")
                elif "qr" in low_query or "scan" in low_query:
                    st.warning("⚠️ **CAUTION:** Scanning a QR code always deducts money from your account. Never scan a QR code to 'receive' money.")
                else:
                    st.info("🔍 Keep your UPI app locked, do not click on unknown SMS refund links, and never share OTPs with anyone!")
    else:
        st.warning("Please record a message or type a query first.")

# Requirements installation note
with st.sidebar:
    st.header("⚙️ Installation Setup")
    st.write("Ensure your `requirements.txt` includes:")
    st.code("streamlit\nstreamlit-mic-recorder\nopenai")





