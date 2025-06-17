import streamlit as st
from utils import supabase_utils as su
import pandas as pd
import io
import re
import json

# --- Authentication Guard ---
if not st.session_state.get("authentication_status"):
    st.warning("Please log in to access this page.")
    st.stop()

# --- Page Setup and Role/User Info ---
st.title("🗂️ View & Approve Expense Reports")
username = st.session_state.get("username")
user_role = st.session_state.get("role")
user_id = st.session_state.get("user_id")

if not user_id:
    st.error("User profile not found in session. Please log in again.")
    st.stop()

# --- Initialize session state for denial workflow ---
if 'denying_report_id' not in st.session_state:
    st.session_state.denying_report_id = None

# --- Data Fetching Based on Role ---
reports_df = pd.DataFrame()
if user_role == 'user':
    st.subheader("Your Submitted Reports")
    reports_df = su.get_reports_for_user(user_id)
elif user_role == 'approver':
    st.subheader("Reports Awaiting Your Approval")
    reports_df = su.get_reports_for_approver(user_id)
elif user_role == 'admin':
    st.subheader("All Company Reports")
    reports_df = su.get_all_reports()

if reports_df.empty:
    st.info("No reports found for your view.")
else:
    # --- Report Selection Dropdown ---
    if 'user' in reports_df.columns:
        reports_df['submitter_name'] = reports_df['user'].apply(lambda x: x.get('name') if isinstance(x, dict) else 'Unknown User')
        reports_df['submitter_name'] = reports_df['submitter_name'].fillna('Unknown User')
        reports_df['display_name'] = reports_df['report_name'] + " by " + reports_df['submitter_name'] + " (Status: " + reports_df['status'] + ")"
    else:
        reports_df['display_name'] = reports_df['report_name'] + " (Status: " + reports_df['status'] + ")"
    
    id_to_display_name_map = {row['id']: row['display_name'] for index, row in reports_df.iterrows()}
    report_id_options = ["-- Select a report --"] + list(id_to_display_name_map.keys())
    
    selected_report_id = st.selectbox(
        "Select a report to view its details:",
        options=report_id_options,
        format_func=lambda report_id: id_to_display_name_map.get(report_id, "-- Select a report --")
    )

    if selected_report_id != "-- Select a report --":
        if st.session_state.denying_report_id and st.session_state.denying_report_id != selected_report_id:
            st.session_state.denying_report_id = None

        st.markdown("---")
        st.header(f"Details for: {id_to_display_name_map[selected_report_id].split(' (')[0]}")
        
        selected_report_details = reports_df[reports_df['id'] == selected_report_id].iloc[0]
        original_expenses_df = su.get_expenses_for_report(selected_report_id)

        # --- Combined Section for Admins/Approvers ---
        if user_role in ['admin', 'approver']:
            # Approval Actions
            st.write(f"**Current Status:** `{selected_report_details['status']}`")
            if pd.notna(selected_report_details.get('approver_comment')):
                st.error(f"**Reason for Denial:** {selected_report_details['approver_comment']}")

            if selected_report_details['status'] == 'Submitted':
                st.write("Actions:")
                bcol1, bcol2, bcol3 = st.columns([1, 1, 5])
                with bcol1:
                    if st.button("Approve", type="primary", use_container_width=True):
                        if su.update_report_status(selected_report_id, "Approved"):
                            st.success("Report Approved!")
                            st.session_state.denying_report_id = None
                            st.rerun()
                with bcol2:
                    if st.button("Deny", use_container_width=True):
                        st.session_state.denying_report_id = selected_report_id
                        st.rerun()
            
            if st.session_state.denying_report_id == selected_report_id:
                st.markdown("---")
                with st.form("denial_form"):
                    st.subheader("Provide Reason for Denial")
                    denial_reason = st.text_area("Reason*", help="This comment will be saved with the report.")
                    ccol1, ccol2 = st.columns(2)
                    with ccol1:
                        if st.form_submit_button("Confirm Denial", type="primary", use_container_width=True):
                            if denial_reason:
                                if su.update_report_status(selected_report_id, "Denied", comment=denial_reason):
                                    st.warning("Report Denied.")
                                    st.session_state.denying_report_id = None
                                    st.rerun()
                            else:
                                st.error("A reason is required.")
                    with ccol2:
                        if st.form_submit_button("Cancel", use_container_width=True):
                            st.session_state.denying_report_id = None
                            st.rerun()
            st.markdown("---")
            
            if not original_expenses_df.empty:
                st.subheader("Edit Expense Details")
                st.info("You can edit values directly in the table below.")
                
                expenses_to_edit = original_expenses_df.copy()
                categories = su.get_all_categories()
                category_names = [""] + [cat['name'] for cat in categories]
                category_map = {cat['name']: cat['id'] for cat in categories}
                
                expenses_to_edit['expense_date'] = pd.to_datetime(expenses_to_edit['expense_date'], errors='coerce')
                for col in ['amount', 'gst_amount', 'pst_amount', 'hst_amount']:
                    if col in expenses_to_edit.columns:
                        expenses_to_edit[col] = pd.to_numeric(expenses_to_edit[col], errors='coerce').fillna(0)
                if 'category_name' not in expenses_to_edit.columns:
                     expenses_to_edit['category_name'] = ""
                expenses_to_edit['category_name'] = expenses_to_edit['category_name'].fillna("").astype(str)
                valid_category_options = set(category_names)
                expenses_to_edit['category_name'] = expenses_to_edit['category_name'].apply(lambda x: x if x in valid_category_options else "")

                editor_key = f"editor_{selected_report_id}"
                edited_expenses_df = st.data_editor(
                    expenses_to_edit,
                    key=editor_key,
                    num_rows="dynamic",
                    hide_index=True,
                    column_config={
                        "id": None, "report_id": None, "user_id": None, "receipt_path": None, "ocr_text": None, 
                        "line_items": None, "created_at": None, "category_id": None,
                        "expense_date": st.column_config.DateColumn("Date", required=True),
                        "vendor": "Vendor", "description": "Purpose",
                        "amount": st.column_config.NumberColumn("Total", format="$%.2f", required=True),
                        "category_name": st.column_config.SelectboxColumn("Category", options=category_names, required=False),
                        "gst_amount": st.column_config.NumberColumn("GST/TPS", format="$%.2f"),
                        "pst_amount": st.column_config.NumberColumn("PST/QST", format="$%.2f"),
                        "hst_amount": st.column_config.NumberColumn("HST/TVH", format="$%.2f"),
                    }
                )
                
                if st.session_state[editor_key].get("edited_rows"):
                    if st.button("Save Expense Changes"):
                        with st.spinner("Saving..."):
                            edited_rows = st.session_state[editor_key]["edited_rows"]
                            all_success = True
                            
                            for row_index, changes in edited_rows.items():
                                expense_id = original_expenses_df.iloc[row_index]['id']
                                
                                if "category_name" in changes:
                                    changes["category_id"] = category_map.get(changes["category_name"])
                                    del changes["category_name"]

                                if not su.update_expense_item(expense_id, changes):
                                    all_success = False
                            
                            if all_success:
                                st.success("Changes saved successfully!")
                                st.rerun()
                            else:
                                st.error("Failed to save one or more changes.")
        
        # --- Static View for Regular Users ---
        else:
            if not original_expenses_df.empty:
                for index, row in original_expenses_df.iterrows():
                    st.markdown(f"#### Expense: {row.get('vendor', 'N/A')} - ${row.get('amount', 0):.2f}")
                    exp_col1, exp_col2 = st.columns(2)
                    with exp_col1:
                        st.write(f"**Date:** {row.get('expense_date', 'N/A')}")
                        st.write(f"**Category:** `{row.get('category_name', 'N/A')}`")
                        st.write(f"**Purpose:** {row.get('description', 'N/A')}")
                    with exp_col2:
                        st.write(f"**GST/TPS:** ${row.get('gst_amount', 0) or 0:.2f}")
                        st.write(f"**PST/QST:** ${row.get('pst_amount', 0) or 0:.2f}")
                        st.write(f"**HST/TVH:** ${row.get('hst_amount', 0) or 0:.2f}")

                    with st.expander("View Details (Line Items & Receipt)"):
                        line_items = []
                        if row.get('line_items') and isinstance(row['line_items'], str):
                            try:
                                line_items = json.loads(row['line_items'])
                            except (json.JSONDecodeError, TypeError):
                                line_items = []
                        if line_items:
                            st.write("**Line Items**")
                            st.dataframe(pd.DataFrame(line_items))
                        else:
                            st.write("*No line items were extracted for this expense.*")
                        
                        if row.get('receipt_path'):
                            st.write("**Receipt File**")
                            receipt_url = su.get_receipt_public_url(row['receipt_path'])
                            if receipt_url:
                                if row['receipt_path'].lower().endswith(('.png', '.jpg', '.jpeg')):
                                    st.image(receipt_url)
                                else:
                                    st.link_button("Download Receipt File", receipt_url)
                        else:
                            st.write("*No receipt was uploaded for this expense.*")
                    st.markdown("---")

        # --- Export Buttons Section ---
        if not original_expenses_df.empty:
            if user_role in ['admin', 'approver']:
                st.subheader("Export This Full Report")
                
                clean_report_name = re.sub(r'[^a-zA-Z0-9\s]', '', id_to_display_name_map[selected_report_id].split(' (')[0]).replace(' ', '_')
                
                desired_export_columns = ["expense_date", "vendor", "description", "amount", "gst_amount", "pst_amount", "hst_amount", "category_name"]
                available_columns_for_export = [col for col in desired_export_columns if col in original_expenses_df.columns]
                
                if available_columns_for_export:
                    export_df = original_expenses_df[available_columns_for_export].copy()
                    btn_col1, btn_col2, btn_col3 = st.columns(3)
                    with btn_col1:
                        csv_data = export_df.to_csv(index=False).encode('utf-8')
                        st.download_button(label="📥 Download as CSV", data=csv_data, file_name=f"{clean_report_name}.csv", mime="text/csv", use_container_width=True)
                    with btn_col2:
                        output = io.BytesIO()
                        with pd.ExcelWriter(output, engine='openpyxl') as writer:
                            export_df.to_excel(writer, index=False, sheet_name='Expenses')
                        excel_data = output.getvalue()
                        st.download_button(label="📄 Download as Excel", data=excel_data, file_name=f"{clean_report_name}.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", use_container_width=True)
                    with btn_col3:
                        submitter_name = selected_report_details.get('submitter_name', 'N/A')
                        xml_data = su.generate_report_xml(selected_report_details, original_expenses_df, submitter_name)
                        st.download_button(label="💿 Download as XML", data=xml_data, file_name=f"{clean_report_name}.xml", mime="application/xml", use_container_width=True)
                else:
                    st.warning("No data with exportable columns found for this report.")
        else:
            st.info("No expense items to display or export for this report.")
