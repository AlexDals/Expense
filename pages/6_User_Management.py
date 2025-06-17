import streamlit as st
from utils import supabase_utils as su
import pandas as pd
import streamlit_authenticator as stauth
import bcrypt

st.title("⚙️ User Management")

# --- Authentication Guard ---
if not st.session_state.get("authentication_status") or st.session_state.get("role") != 'admin':
    st.error("You do not have permission to access this page.")
    st.stop()

# --- Admin User Creation Form ---
with st.expander("➕ Create a New User"):
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
                    hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode('utf-8')
                    if su.register_user(new_username, new_name, new_email, hashed_password, new_role):
                        st.success(f"User '{new_username}' created successfully!")
                        st.rerun()
                except Exception as e:
                    st.error(f"A critical error occurred during user creation: {e}")

st.markdown("---")

# --- Existing User Editing Logic ---
st.subheader("Edit Existing Users")
all_users_df = su.get_all_users()
approvers = su.get_all_approvers()
approver_dict = {approver['name']: approver['id'] for approver in approvers}
approver_names = ["None"] + list(approver_dict.keys())

if all_users_df.empty:
    st.warning("No users found.")
    st.stop()

# Prepare dataframe for editing
id_to_name_map = {v: k for k, v in approver_dict.items()}
all_users_df['approver_name'] = all_users_df['approver_id'].map(id_to_name_map).fillna("None")
# Ensure department column exists and fill null values for the editor
if 'department' not in all_users_df.columns:
    all_users_df['department'] = None
all_users_df['department'] = all_users_df['department'].fillna("")


# Use a separate dataframe for editing to compare changes
edited_df = st.data_editor(
    all_users_df,
    column_config={
        "id": None, "approver_id": None,
        "role": st.column_config.SelectboxColumn("Role", options=["user", "approver", "admin"], required=True),
        "approver_name": st.column_config.SelectboxColumn("Approver", options=approver_names),
        "department": st.column_config.TextColumn("Department", required=False) # NEW column
    },
    hide_index=True,
    key="user_editor"
)

if st.button("Save All User Changes"):
    # Find changed rows by comparing the data editor's state with the original dataframe
    changes = []
    original_df_indexed = all_users_df.set_index('id')
    edited_df_indexed = edited_df.set_index('id')
    
    # Iterate through the edited dataframe to find changes
    for user_id, edited_row in edited_df_indexed.iterrows():
        original_row = original_df_indexed.loc[user_id]
        if not original_row.equals(edited_row):
            changes.append(edited_row)
    
    if not changes:
        st.info("No changes to save.")
    else:
        with st.spinner("Saving..."):
            all_success = True
            for changed_row in changes:
                user_id = changed_row.name # Get ID from the index
                new_approver_id = approver_dict.get(changed_row['approver_name'])
                
                # Call the updated details function
                if not su.update_user_details(user_id, changed_row['role'], new_approver_id, changed_row['department']):
                    all_success = False
            
            if all_success:
                st.success("All changes saved successfully!")
                st.rerun()
            else:
                st.error("One or more changes could not be saved.")
