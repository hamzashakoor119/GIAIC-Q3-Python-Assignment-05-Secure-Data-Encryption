import streamlit as st
import hashlib
import json
from cryptography.fernet import Fernet

# Initializing session states
if "KEY" not in st.session_state:
    st.session_state.KEY = Fernet.generate_key()
cipher = Fernet(st.session_state.KEY)

if "users" not in st.session_state:
    st.session_state.users = {}  # Format: {username: {"password": hashed, "data": {encrypted: hashed_passkey}}}

if "current_user" not in st.session_state:
    st.session_state.current_user = None

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "current_page" not in st.session_state:
    st.session_state.current_page = "Login"

# Helper functions
def hash_text(text):
    return hashlib.sha256(text.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# Title - Centered and Blue
st.markdown("<h1 style='text-align: center; color: blue;'>Code With Hamza</h1>", unsafe_allow_html=True)
st.title("🔐 Secure Data Vault By Hamza")

menu = ["Login", "Sign Up", "Store Data", "Retrieve Data", "Logout"]
choice = st.sidebar.selectbox("Menu", menu, index=menu.index(st.session_state.current_page))
st.session_state.current_page = choice

# -------------------- SIGN UP --------------------
if choice == "Sign Up":
    st.subheader("📝 User Registration")
    username = st.text_input("Choose a Username")
    password = st.text_input("Choose a Password", type="password")
    if st.button("Register"):
        if username in st.session_state.users:
            st.warning("⚠️ Username already exists.")
        elif username and password:
            st.session_state.users[username] = {
                "password": hash_text(password),
                "data": {}
            }
            st.success("✅ Registered successfully! You can now login.")
        else:
            st.error("Please fill all fields.")

# -------------------- LOGIN --------------------
elif choice == "Login":
    st.subheader("🔑 User Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username in st.session_state.users and st.session_state.users[username]["password"] == hash_text(password):
            st.session_state.current_user = username
            st.success(f"✅ Welcome, {username}!")
            st.session_state.current_page = "Store Data"
        else:
            st.error("❌ Invalid credentials")

# -------------------- STORE DATA --------------------
elif choice == "Store Data":
    if not st.session_state.current_user:
        st.warning("Please login first.")
    else:
        st.subheader("💾 Store Encrypted Data")
        user_data = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Enter a passkey", type="password")
        if st.button("Encrypt & Store"):
            if user_data and passkey:
                encrypted = encrypt_data(user_data)
                hashed_pass = hash_text(passkey)
                st.session_state.users[st.session_state.current_user]["data"][encrypted] = hashed_pass
                st.success("✅ Data encrypted and stored.")
                st.write(f"🔐 Save this encrypted data: `{encrypted}`")
            else:
                st.error("⚠️ All fields are required.")

# -------------------- RETRIEVE DATA --------------------
elif choice == "Retrieve Data":
    if not st.session_state.current_user:
        st.warning("Please login first.")
    else:
        st.subheader("🔍 Retrieve Encrypted Data")
        encrypted_text = st.text_area("Paste Encrypted Data")
        passkey = st.text_input("Enter Passkey", type="password")
        if st.button("Decrypt"):
            user_data = st.session_state.users[st.session_state.current_user]["data"]
            if encrypted_text in user_data and user_data[encrypted_text] == hash_text(passkey):
                decrypted = decrypt_data(encrypted_text)
                st.success("✅ Decryption successful")
                st.write("🔓 Decrypted Data:", decrypted)
                st.session_state.failed_attempts = 0
            else:
                st.session_state.failed_attempts += 1
                st.error(f"❌ Wrong passkey or data. Attempts: {st.session_state.failed_attempts}/3")
                if st.session_state.failed_attempts >= 3:
                    st.warning("🚫 Too many failed attempts. Please login again.")
                    st.session_state.current_user = None
                    st.session_state.current_page = "Login"

# -------------------- LOGOUT --------------------
elif choice == "Logout":
    st.session_state.current_user = None
    st.session_state.current_page = "Login"
    st.success("👋 Logged out successfully.")