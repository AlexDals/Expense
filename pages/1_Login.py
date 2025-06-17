import streamlit as st

st.title("Employee Expense Reporting")
st.write("Please log in to access your dashboard.")

# --- Retrieve the authenticator object from session state ---
authenticator = st.session_state.get('authenticator')
if not authenticator:
    st.error("Authentication system not initialized. Please run the main app.py file.")
    st.stop()

# --- Render the login form ---
# This call updates session state and triggers a rerun, which app.py will handle.
authenticator.login()

# --- Display messages based on login status ---
if st.session_state.get("authentication_status") is False:
    st.error("Username/password is incorrect.")

# Note: There is no st.switch_page() here. The redirection is now automatic.
