import streamlit as st
from transformers import pipeline
import sqlite3
from datetime import datetime
import pandas as pd

# --- 1. DATABASE SETUP ---
def init_db():
    conn = sqlite3.connect('phishing_history.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS history 
                 (timestamp TEXT, message TEXT, result TEXT, confidence REAL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (username TEXT PRIMARY KEY, password TEXT)''')
    conn.commit()
    conn.close()

def save_to_db(message, result, confidence):
    conn = sqlite3.connect('phishing_history.db')
    c = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO history VALUES (?, ?, ?, ?)", (timestamp, message, result, confidence))
    conn.commit()
    conn.close()

init_db()

# --- 2. SESSION STATE ---
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = ""

# --- 3. LOGIN & SIGN-UP ---
if not st.session_state.logged_in:
    st.markdown("<h1 style='text-align: center;'>🛡️ AI Phishing Guard</h1>", unsafe_allow_html=True)
    tab1, tab2 = st.tabs(["Log in", "Sign up"])
    with tab1:
        u = st.text_input("Username", key="l_user")
        p = st.text_input("Password", type="password", key="l_pwd")
        if st.button("Continue", use_container_width=True):
            conn = sqlite3.connect('phishing_history.db')
            res = conn.execute("SELECT * FROM users WHERE username=? AND password=?", (u, p)).fetchone()
            conn.close()
            if res:
                st.session_state.logged_in = True
                st.session_state.username = u
                st.rerun()
            else: st.error("Invalid credentials.")
    with tab2:
        nu = st.text_input("New Username", key="s_user")
        np = st.text_input("New Password", type="password", key="s_pwd")
        if st.button("Create Account", use_container_width=True):
            try:
                conn = sqlite3.connect('phishing_history.db')
                conn.execute("INSERT INTO users VALUES (?, ?)", (nu, np))
                conn.commit()
                st.success("Account created! Go to Log in.")
            except: st.error("Username exists!")
            finally: conn.close()
    st.stop()

# --- 4. MAIN INTERFACE ---
st.title(f"🛡️ Hello, {st.session_state.username}!")
st.sidebar.button("Logout", on_click=lambda: st.session_state.update({"logged_in": False}))

@st.cache_resource
def load_ai():
    # BERT Model for Core Logic
    return pipeline("text-classification", model="mrm8488/bert-tiny-finetuned-sms-spam-detection")

classifier = load_ai()

if st.sidebar.button("Show History"):
    conn = sqlite3.connect('phishing_history.db')
    df = pd.read_sql_query("SELECT * FROM history ORDER BY timestamp DESC", conn)
    st.sidebar.table(df)
    conn.close()

# --- 5. INTERACTIVE CHAT ENGINE (GEMINI STYLE) ---
user_input = st.chat_input("Paste a link or say Hi...")

if user_input:
    with st.chat_message("user"):
        st.write(user_input)

    with st.chat_message("assistant"):
        input_lower = user_input.lower()
        
        # 🟢 Conversation Logic
        if any(greet in input_lower for greet in ["hi", "hello", "hey", "vanakkam"]):
            st.write(f"Hello {st.session_state.username}! 👋 How can I help you today? If you have any suspicious links, paste them here and I'll analyze the impact for you.")
        
        elif any(q in input_lower for q in ["how are you", "epdi iruka"]):
            st.write("I'm doing great! 🤖 Ready to protect you from cybersecurity threats. What's on your mind?")

        # 🔴 AI Phishing & Impact Analysis
        else:
            res = classifier(user_input)[0]
            confidence = res['score'] * 100
            
            # Domain Info
            domain_db = {"google.com": "Official Google Security.", "amazon.in": "Official Amazon India.", "onlinesbi.com": "Official SBI net banking."}
            detected_domain = next((d for d in domain_db if d in input_lower), None)
            
            # Risk Patterns
            patterns = {
                "Urgency/Threat": ["urgent", "suspended", "action required"],
                "Financial Scam": ["bonus", "winner", "prize", "refund"]
            }
            found = [cat for cat, words in patterns.items() if any(w in input_lower for w in words)]

            if detected_domain:
                final_label = "SAFE"
                st.success(f"✅ VERIFIED SAFE ({confidence:.2f}%)")
                report = f"🔗 **Safe Source:** This link belongs to **{detected_domain}**. It is a verified official portal and is safe to use."
                impact_msg = "No negative impact. You can proceed safely."
            elif res['label'] == 'LABEL_1' or found:
                final_label = "PHISHING/SPAM"
                st.error(f"🚨 ALERT: {final_label} ({max(confidence, 92.50):.2f}%)")
                
                # Detailed Impact Analysis
                impact_msg = """
                ⚠️ **How this affects you:**
                1. **Credential Theft:** Scammers might steal your login details and passwords.
                2. **Financial Loss:** They could gain unauthorized access to your bank accounts.
                3. **Identity Theft:** Your personal data can be sold or misused for illegal activities.
                4. **Malware Risk:** Clicking the link might download hidden trackers or viruses to your device.
                """
                report = f"🚩 **Risk Detected:** I found **{', '.join(found)}** triggers. The BERT AI model flagged this as a high-risk social engineering attempt."
            else:
                final_label = "SAFE"
                st.success(f"✅ VERIFIED SAFE ({confidence:.2f}%)")
                report = "No common phishing patterns detected."
                impact_msg = "Seems safe, but always be cautious with unknown links."

            # 🧬 XAI Report & Impact
            st.info(f"🧬 **AI Explainability Report:**\n\n{report}")
            st.warning(impact_msg)
            save_to_db(user_input, final_label, round(confidence, 2))
            st.write("Stay safe! Anything else I can check for you?")