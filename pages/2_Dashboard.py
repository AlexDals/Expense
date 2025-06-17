import streamlit as st
from utils import supabase_utils as su
import pandas as pd

# --- Authentication Guard ---
if not st.session_state.get("authentication_status"):
    st.warning("Please log in to access the dashboard.")
    st.stop()

# --- Retrieve authenticator and user info from session state ---
authenticator = st.session_state.get('authenticator')
name = st.session_state.get("name")
username = st.session_state.get("username")
user_id = st.session_state.get("user_id")

# A second guard to ensure the authenticator object exists
if not authenticator or not user_id:
    st.error("Session data not found. Please log in again.")
    st.stop()

# --- Sidebar ---
st.sidebar.title(f"Welcome {name}!")

# --- DEFINITIVE FIX: Complete Logout Logic ---
# The logout method returns True if the button is clicked.
if authenticator.logout("Logout", "sidebar"):
    # When logout is successful, manually clear all our custom session variables
    st.session_state['role'] = None
    st.session_state['user_id'] = None
    st.session_state['user_credentials'] = None
    st.success("You have been successfully logged out.")
    st.rerun() # Force a rerun to immediately go to the login page

# --- Page Content ---
st.title("🏠 Dashboard")
st.write("Navigate using the sidebar to create a new report or view existing reports.")
st.markdown("---")

st.subheader("Your Dashboard")
try:
    user_reports_df = su.get_reports_for_user(user_id)
    if not user_reports_df.empty:
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Total Reports Submitted", len(user_reports_df))
        with col2:
            st.metric("Total Expenses Claimed", f"${user_reports_df['total_amount'].sum():,.2f}")
    else:
        st.info("No reports submitted yet. Go to 'New Report' to create one!")
except Exception as e:
    st.error(f"Could not load dashboard: {e}")
