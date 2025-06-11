import streamlit as st
from utils import supabase_utils as su

st.title("Employee Expense Reporting")
st.write("Please log in to access your dashboard.")

# --- Retrieve the authenticator object from the session state ---
# This was created and configured in the main app.py script.
if 'authenticator' not in st.session_state:
    st.error("Authenticator not found. Please start from the main app page.")
    st.stop()

authenticator = st.session_state['authenticator']

# --- Render Login Widget ---
authenticator.login()

if st.session_state.get("authentication_status") is False:
    st.error("Username/password is incorrect")

elif st.session_state.get("authentication_status"):
    # This logic runs immediately after a successful login.
    username = st.session_state.get("username")
    
    # Manually fetch and set the user's role into the session state.
    if username and ('role' not in st.session_state or st.session_state.role is None):
         st.session_state["role"] = su.get_user_role(username)
    
    # Switch to the dashboard page upon successful login.
    st.switch_page("pages/2_Dashboard.py")
