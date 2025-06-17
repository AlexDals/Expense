import streamlit as st
from utils import supabase_utils as su
from streamlit_authenticator import Authenticate

# --- PAGE CONFIGURATION ---
st.set_page_config(layout="wide", page_title="Expense Reporting")

# --- USER AUTHENTICATION SETUP ---
if 'authenticator' not in st.session_state:
    try:
        user_credentials = su.fetch_all_users_for_auth()
        cookie_config = st.secrets.get("cookie", {})
        
        authenticator = Authenticate(
            user_credentials,
            cookie_config.get('name', 'some_cookie_name'),
            cookie_config.get('key', 'some_random_key'),
            cookie_config.get('expiry_days', 30),
        )
        st.session_state['authenticator'] = authenticator
        st.session_state['user_credentials'] = user_credentials
    except Exception as e:
        st.error(f"An error occurred during authentication setup: {e}")
        st.stop()

# --- ROLE & ID CHECK AFTER LOGIN ---
# This block runs on every rerun to ensure role/id are set if the user is logged in.
if st.session_state.get("authentication_status"):
    if 'role' not in st.session_state or st.session_state.role is None:
        username = st.session_state.get("username")
        if username:
            user_credentials = st.session_state.get('user_credentials', {})
            user_details = user_credentials.get("usernames", {}).get(username, {})
            st.session_state["role"] = user_details.get("role")
            st.session_state["user_id"] = user_details.get("id")

# --- PROGRAMMATIC NAVIGATION ---
is_logged_in = st.session_state.get("authentication_status")
user_role = st.session_state.get("role")

# Define all possible pages as objects
login_page = st.Page("pages/1_Login.py", title="Login", icon="🔑", default=(not is_logged_in))
dashboard_page = st.Page("pages/2_Dashboard.py", title="Dashboard", icon="🏠", default=is_logged_in)
new_report_page = st.Page("pages/3_New_Report.py", title="New Report", icon="📄")
view_reports_page = st.Page("pages/4_View_Reports.py", title="View Reports", icon="🗂️")
register_page = st.Page("pages/5_Register.py", title="Register", icon="🔑")
user_management_page = st.Page("pages/6_User_Management.py", title="User Management", icon="⚙️")
category_management_page = st.Page("pages/7_Category_Management.py", title="Category Management", icon="📈")

# Define the page lists for each state
logged_out_pages = [login_page, register_page]
user_app_pages = [dashboard_page, new_report_page, view_reports_page]
admin_app_pages = [dashboard_page, new_report_page, view_reports_page, user_management_page, category_management_page]

# Select the correct list of pages based on the user's role and login status
pages_to_show = []
if not is_logged_in:
    pages_to_show = logged_out_pages
else:
    if user_role == 'admin':
        pages_to_show = admin_app_pages
    else: # This applies to both 'user' and 'approver' roles
        pages_to_show = user_app_pages

# Create and run the navigation
pg = st.navigation(pages_to_show)
pg.run()
