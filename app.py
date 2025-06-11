import streamlit as st
from utils import supabase_utils as su
from streamlit_authenticator import Authenticate

# --- PAGE CONFIGURATION ---
# This MUST be the first Streamlit command.
st.set_page_config(layout="wide", page_title="Expense Reporting")

# --- USER AUTHENTICATION SETUP ---
# Initialize or retrieve the authenticator from the session state.
if 'authenticator' not in st.session_state:
    try:
        user_credentials = su.fetch_all_users_for_auth()
        cookie_config = st.secrets.get("cookie", {})
        
        authenticator = Authenticate(
            user_credentials,
            cookie_config.get('name', 'some_cookie_name'), # Provide defaults
            cookie_config.get('key', 'some_random_key'),
            cookie_config.get('expiry_days', 30),
        )
        st.session_state['authenticator'] = authenticator
    except Exception as e:
        st.error(f"An error occurred during authentication setup: {e}")
        st.stop()
else:
    authenticator = st.session_state['authenticator']

# --- ROLE CHECK AFTER LOGIN ---
# This block runs every time to ensure the role is in the session state if logged in.
if st.session_state.get("authentication_status"):
    if 'role' not in st.session_state or st.session_state.role is None:
        username = st.session_state.get("username")
        if username:
            st.session_state["role"] = su.get_user_role(username)

# --- PROGRAMMATIC NAVIGATION ---
# A helper variable to make the logic cleaner
is_logged_in = st.session_state.get("authentication_status")

# Define all pages, with a DYNAMIC default page based on login status
login_page = st.Page("pages/1_Login.py", title="Login", icon="🔑", default=(not is_logged_in))
dashboard_page = st.Page("pages/2_Dashboard.py", title="Dashboard", icon="🏠", default=is_logged_in)
new_report_page = st.Page("pages/3_New_Report.py", title="New Report", icon="📄")
view_reports_page = st.Page("pages/4_View_Reports.py", title="View Reports", icon="🗂️")
register_page = st.Page("pages/5_Register.py", title="Register", icon="🔑")
admin_page = st.Page("pages/6_User_Management.py", title="User Management", icon="⚙️")

# Build the navigation list based on login status and role.
if is_logged_in:
    # If the user is logged in, show the main app pages.
    nav_pages = [dashboard_page, new_report_page, view_reports_page]
    if st.session_state.get("role") == 'admin':
        nav_pages.append(admin_page)
else:
    # If the user is logged out, show only the account pages.
    nav_pages = [login_page, register_page]

# Create and run the navigation
pg = st.navigation(nav_pages)
pg.run()
