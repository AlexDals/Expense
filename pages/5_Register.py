import streamlit as st
import streamlit_authenticator as stauth
import re
from utils import supabase_utils as su
import bcrypt

# The redundant st.set_page_config() call has been removed.
st.title("Register New User")

if st.session_state.get("authentication_status"):
    st.warning("You are already logged in. Please log out to register a new user.")
    st.stop()

EMAIL_REGEX = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"

with st.form("registration_form"):
    st.write("Please fill out the details below to register.")
    email = st.text_input("Email*")
    name = st.text_input("Full Name*")
    username = st.text_input("Username* (no spaces)")
    password = st.text_input("Password*", type="password")
    confirm_password = st.text_input("Confirm Password*", type="password")
    submitted = st.form_submit_button("Register")

if submitted:
    if not all([email, name, username, password, confirm_password]):
        st.error("Please fill out all mandatory fields.")
    elif password != confirm_password:
        st.error("Passwords do not match.")
    elif not re.match(EMAIL_REGEX, email):
        st.error("Invalid email address.")
    elif " " in username or not username.isalnum():
        st.error("Username must be alphanumeric with no spaces.")
    else:
        try:
            password_bytes = password.encode('utf-8')
            salt = bcrypt.gensalt()
            hashed_password_bytes = bcrypt.hashpw(password_bytes, salt)
            hashed_password_str = hashed_password_bytes.decode('utf-8')
            if su.register_user(username, name, email, hashed_password_str, role='user'):
                st.success("Registration successful! You can now log in.")
                st.balloons()
        except Exception as e:
            st.error(f"A critical error occurred: {e}")
