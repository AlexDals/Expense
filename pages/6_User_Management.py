import streamlit as st
from utils import supabase_utils as su
import pandas as pd
import streamlit_authenticator as stauth
import bcrypt

# The redundant st.set_page_config() call has been removed.

st.title("⚙️ User Management")

# --- Authentication and Role Check ---
if 'authentication_status' not in st.session_state or not st.session_state['authentication_status']:
    st.warning("Please log in to access this page.")
    st.stop()
elif st.session_state.get("role") != 'admin':
    st.error("You do not have permission to access this page.")
    st.stop()

# --- Admin User Creation Form ---
with st.expander("Create a New User", expanded=False):
    with st.form("admin_create_user_form", clear_on_submit=True):
        st.subheader("New User Details")
        new_name = st.text_input("Full Name*")
        new_username = st.text_input("Username* (no spaces)")
        new_email = st.text_input("Email*")
        new_password = st.text_input("Password*", type="password")
        new_role = st.selectbox("Assign Role*", options=["user", "approver", "admin"])
        
        create_submitted = st.form_submit_button("Create User")

        if create_submitted:
            if not all([new_email, new_name, new_username, new_password, new_role]):
                st.error("Please fill out all fields to create a user.")
            else:
                try:
                    password_bytes = new_password.encode('utf-8')
                    salt = bcrypt.gensalt()
                    hashed_password = bcrypt.hashpw(password_bytes, salt).decode('utf-8')
                    
                    if su.register_user(new_username, new_name, new_email, hashed_password, new_role):
                        st.success(f"User '{new_username}' created successfully with role '{new_role}'.")
                        st.rerun()
                except Exception as e:
                    st.error(f"A critical error occurred during user creation: {e}")

st.markdown("---")

# --- Existing User Editing Logic ---
st.subheader("Edit Existing Users")
st.info("Edit user roles and assign approvers below. Changes are saved automatically.")

all_users_df = su.get_all_users()
approvers = su.get_all_approvers()
approver_dict = {approver['name']: approver['id'] for approver in approvers}
approver_names = ["None"] + list(approver_dict.keys())

if all_users_df.empty:
    st.warning("No users found.")
    st.stop()

id_to_name_map = {v: k for k, v in approver_dict.items()}
all_users_df['approver_name'] = all_users_df['approver_id'].map(id_to_name_map).fillna("None")

edited_df = st.data_editor(
    all_users_df,
    column_config={
        "id": None, "approver_id": None,
        "role": st.column_config.SelectboxColumn("Role", options=["user", "approver", "admin"], required=True),
        "approver_name": st.column_config.SelectboxColumn("Approver", options=approver_names, required=True),
    },
    hide_index=True,
    key="user_editor"
)

if not all_users_df.equals(edited_df):
    diff = all_users_df.merge(edited_df, indicator=True, how='outer').loc[lambda x : x['_merge']=='right_only']
    
    for index, row in diff.iterrows():
        user_id = row['id']
        new_role = row['role']
        new_approver_name = row['approver_name']
        new_approver_id = approver_dict.get(new_approver_name)
        
        if su.update_user_details(user_id, new_role, new_approver_id):
            st.success(f"Details for user '{row['username']}' updated!")
            st.rerun()
        else:
            st.error(f"Failed to update details for user '{row['username']}'.")
