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
user_id = su.get_user_id_by_username(username)

if not user_id:
    st.error("Could not identify user. Please log in again.")
    st.stop()

# --- Data Fetching Based on Role ---
reports_df = pd.DataFrame()
page_subheader = ""

if user_role == 'user':
    page_subheader = "Your Submitted Reports"
    reports_df = su.get_reports_for_user(user_id)
elif user_role == 'approver':
    page_subheader = "Reports Awaiting Your Approval"
    reports_df = su.get_reports_for_approver(user_id)
elif user_role == 'admin':
    page_subheader = "All Company Reports"
    reports_df = su.get_all_reports()

st.subheader(page_subheader)

# --- Display Reports and Details ---
if reports_df.empty:
    st.info("No reports found for your view.")
else:
    # Add a user-friendly display name to the DataFrame for the selectbox
    reports_df['display_name'] = reports_df['report_name'] + " (Status: " + reports_df['status'] + ")"
    report_options = {row['display_name']: row['id'] for index, row in reports_df.iterrows()}
    report_options_list = ["-- Select a report --"] + list(report_options.keys())
    
    selected_report_display_name = st.selectbox("Select a report to view its details:", options=report_options_list)

    if selected_report_display_name != "-- Select a report --":
        selected_report_id = report_options[selected_report_display_name]
        
        # Extract a clean report name for exported filenames
        clean_report_name = re.sub(r'[^a-zA-Z0-9\s]', '', selected_report_display_name.split(' (')[0]).replace(' ', '_')
        
        st.markdown("---")
        st.header(f"Details for: {selected_report_display_name.split(' (')[0]}")
        
        selected_report_details = reports_df[reports_df['id'] == selected_report_id].iloc[0]
        expenses_df = su.get_expenses_for_report(selected_report_id)
        
        # --- Approval Action Buttons (for approvers and admins) ---
        if user_role in ['admin', 'approver']:
            st.write(f"**Current Status:** `{selected_report_details['status']}`")
            
            # Only show action buttons if the status is 'Submitted'
            if selected_report_details['status'] == 'Submitted':
                st.write("Actions:")
                col1, col2, col3 = st.columns([1, 1, 5])
                with col1:
                    if st.button("Approve", type="primary", use_container_width=True):
                        if su.update_report_status(selected_report_id, "Approved"):
                            st.success("Report Approved!")
                            st.rerun()
                with col2:
                    if st.button("Deny", use_container_width=True):
                        if su.update_report_status(selected_report_id, "Denied"):
                            st.warning("Report Denied.")
                            st.rerun()
            st.markdown("---")

        # --- Display Expense Items ---
        if not expenses_df.empty:
            for index, row in expenses_df.iterrows():
                st.markdown(f"#### Expense: {row.get('vendor', 'N/A')} - ${row.get('amount', 0):.2f}")
                
                exp_col1, exp_col2 = st.columns(2)
                with exp_col1:
                    st.write(f"**Date:** {row.get('expense_date', 'N/A')}")
                    st.write(f"**Purpose:** {row.get('description', 'N/A')}")
                with exp_col2:
                    st.write(f"**GST/TPS:** ${row.get('gst_amount', 0) or 0:.2f}")
                    st.write(f"**PST/QST:** ${row.get('pst_amount', 0) or 0:.2f}")
                    st.write(f"**HST/TVH:** ${row.get('hst_amount', 0) or 0:.2f}")

                with st.expander("View Details (Line Items & Receipt)"):
                    line_items = []
                    # The line_items are stored as a JSON string, so we must load it
                    if row.get('line_items') and isinstance(row['line_items'], str):
                        try:
                            line_items = json.loads(row['line_items'])
                        except json.JSONDecodeError:
                            line_items = []
                    
                    if line_items and isinstance(line_items, list) and len(line_items) > 0:
                        st.write("**Line Items**")
                        st.dataframe(pd.DataFrame(line_items))
                    else:
                        st.write("*No line items were extracted for this expense.*")

                    if row.get('receipt_path'):
                        st.write("**Receipt File**")
                        receipt_url = su.get_receipt_public_url(row['receipt_path'])
                        if receipt_url:
                            # Display images directly, provide a link for other file types like PDFs
                            if row['receipt_path'].lower().endswith(('.png', '.jpg', '.jpeg')):
                                st.image(receipt_url)
                            else:
                                st.link_button("Download Receipt File", receipt_url)
                    else:
                        st.write("*No receipt was uploaded for this expense.*")
                
                st.markdown("---")

            # --- Export Buttons Section ---
            st.subheader("Export This Full Report")
            
            # Prepare a clean DataFrame for export
            export_df = expenses_df[[
                "expense_date", "vendor", "description", "amount", 
                "gst_amount", "pst_amount", "hst_amount"
            ]].copy()

            btn_col1, btn_col2 = st.columns(2)
            with btn_col1:
                csv_data = export_df.to_csv(index=False).encode('utf-8')
                st.download_button(
                    label="📥 Download as CSV",
                    data=csv_data,
                    file_name=f"{clean_report_name}.csv",
                    mime="text/csv",
                    use_container_width=True
                )
            with btn_col2:
                output = io.BytesIO()
                with pd.ExcelWriter(output, engine='openpyxl') as writer:
                    export_df.to_excel(writer, index=False, sheet_name='Expenses')
                excel_data = output.getvalue()
                st.download_button(
                    label="📄 Download as Excel",
                    data=excel_data,
                    file_name=f"{clean_report_name}.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    use_container_width=True
                )
        else:
            st.info("No expense items found for this report.")
