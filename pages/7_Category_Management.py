import streamlit as st
from utils import supabase_utils as su
import pandas as pd

st.title("📈 Category & GL Account Management")

# --- Authentication Guard ---
if not st.session_state.get("authentication_status") or st.session_state.get("role") != 'admin':
    st.error("You do not have permission to access this page.")
    st.stop()

# --- Create New Category Form ---
with st.expander("➕ Create a New Category"):
    with st.form("new_category_form", clear_on_submit=True):
        name = st.text_input("Category Name*")
        gl_account = st.number_input("GL Account Number", step=1, format="%d")
        submitted = st.form_submit_button("Create Category")
        if submitted:
            if name:
                if su.add_category(name, gl_account):
                    st.success(f"Category '{name}' created successfully!")
                    st.rerun() # Rerun to update the table below
            else:
                st.error("Category Name is a required field.")

st.markdown("---")

# --- Edit Existing Categories ---
st.subheader("Edit Existing Categories")
categories = su.get_all_categories()

if not categories:
    st.info("No categories created yet. Use the form above to add one.")
else:
    # Use st.data_editor to allow edits, additions, and deletions
    edited_data = st.data_editor(
        pd.DataFrame(categories),
        num_rows="dynamic", # Allow adding and deleting rows
        use_container_width=True,
        column_config={
            "id": None, # Hide the ID column
            "name": st.column_config.TextColumn("Category Name", required=True),
            "gl_account": st.column_config.NumberColumn("GL Account", required=True, format="%d"),
        },
        key="category_editor"
    )
    
    if st.button("Save All Changes"):
        with st.spinner("Saving..."):
            original_df = pd.DataFrame(categories)
            edited_df = pd.DataFrame(edited_data)
            
            # Simple but effective way to sync: delete all and re-insert all
            # This is not efficient for very large datasets, but safe and simple for this use case.
            all_success = True
            # Delete removed categories
            original_ids = set(original_df['id'].dropna())
            edited_ids = set(edited_df['id'].dropna())
            deleted_ids = original_ids - edited_ids
            for cat_id in deleted_ids:
                if not su.delete_category(cat_id):
                    all_success = False
            
            # Update existing or add new ones
            for index, row in edited_df.iterrows():
                name = row['name']
                gl = row['gl_account']
                cat_id = row.get("id")

                if pd.isna(cat_id): # New row
                    if not su.add_category(name, gl):
                        all_success = False
                else: # Existing row
                    if not su.update_category(cat_id, name, gl):
                        all_success = False

            if all_success:
                st.success("All changes saved successfully!")
            else:
                st.error("One or more changes could not be saved. Please check for duplicate names.")
            
            st.rerun()
