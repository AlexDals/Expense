import streamlit as st
from utils import ocr_utils, supabase_utils as su
import pandas as pd
from datetime import date

# Authentication Guard
if not st.session_state.get("authentication_status"):
    st.warning("Please log in to access this page.")
    st.stop()

# Page Setup
st.title("📄 Create New Expense Report")
username = st.session_state.get("username")
user_id = su.get_user_id_by_username(username)
if not user_id:
    st.error("Could not identify user."); st.stop()
if 'current_report_items' not in st.session_state:
    st.session_state.current_report_items = []

# Fetch Categories for dropdowns
categories = su.get_all_categories()
category_names = [""] + [cat['name'] for cat in categories]
category_dict = {cat['name']: cat['id'] for cat in categories}

# Main UI
report_name = st.text_input("Report Name/Purpose*", placeholder="e.g., Office Supplies - June")
st.subheader("Add Expense/Receipt")
uploaded_receipt = st.file_uploader("Upload Receipt (Image or PDF)", type=["png", "jpg", "jpeg", "pdf"])

parsed_data, raw_text, receipt_path_for_db = {}, "", None
if 'line_item_df' not in st.session_state:
    st.session_state.line_item_df = pd.DataFrame()

if uploaded_receipt:
    with st.spinner("Processing OCR and uploading receipt..."):
        raw_text, parsed_data = ocr_utils.extract_and_parse_file(uploaded_receipt)
        with st.expander("View Raw Extracted Text"):
            st.text_area("OCR Output", raw_text, height=300)
        if "error" in parsed_data:
            st.error(parsed_data["error"]); parsed_data = {}
        else:
            st.success("OCR processing complete. Please verify.")
        receipt_path_for_db = su.upload_receipt(uploaded_receipt, username)
        if receipt_path_for_db: st.success("Receipt uploaded successfully!")
        else: st.error("Failed to upload receipt.")
        # Store initial parsed line items in session state
        st.session_state.line_item_df = pd.DataFrame(parsed_data.get("line_items", []))
else:
    # Default structure
    if st.button("Clear form"):
        st.session_state.line_item_df = pd.DataFrame()
        parsed_data = {"date": None, "vendor": "", "total_amount": 0.0, "gst_amount": 0.0, "pst_amount": 0.0, "hst_amount": 0.0, "line_items": []}


# Form for adding the expense
with st.form("expense_item_form"):
    st.write("Verify the extracted data below. You can assign a category to each line item.")
    
    # Overall Expense Fields
    overall_category = st.selectbox("Overall Expense Category*", options=category_names, help="Select the main category for this entire receipt.")
    col1, col2 = st.columns(2)
    with col1:
        parsed_timestamp = pd.to_datetime(parsed_data.get("date"), errors='coerce')
        initial_date = date.today() if pd.isna(parsed_timestamp) else parsed_timestamp.date()
        expense_date = st.date_input("Expense Date", value=initial_date)
        vendor = st.text_input("Vendor Name", value=parsed_data.get("vendor", ""))
        description = st.text_area("Purpose/Description", placeholder="e.g., Monthly office supplies")
    with col2:
        ocr_amount = float(parsed_data.get("total_amount", 0.0))
        initial_value = max(0.01, ocr_amount)
        amount = st.number_input("Amount (Total)", min_value=0.01, value=initial_value, format="%.2f")
        st.markdown("###### Taxes (Editable)")
        tax_col1, tax_col2, tax_col3 = st.columns(3)
        with tax_col1: gst_amount = st.number_input("GST/TPS", min_value=0.0, value=float(parsed_data.get("gst_amount", 0.0)), format="%.2f")
        with tax_col2: pst_amount = st.number_input("PST/QST", min_value=0.0, value=float(parsed_data.get("pst_amount", 0.0)), format="%.2f")
        with tax_col3: hst_amount = st.number_input("HST/TVH", min_value=0.0, value=float(parsed_data.get("hst_amount", 0.0)), format="%.2f")

    # Line Item Category Assignment
    if not st.session_state.line_item_df.empty:
        st.markdown("---")
        st.subheader("Assign Categories to Line Items")
        edited_line_items_df = st.data_editor(
            st.session_state.line_item_df,
            column_config={"category": st.column_config.SelectboxColumn("Category", options=category_names, required=False)},
            hide_index=True, key="line_item_editor"
        )
        st.session_state.edited_line_items = edited_line_items_df.to_dict('records')

    submitted_item = st.form_submit_button("Add Item to Report")
    if submitted_item:
        if vendor and amount > 0 and overall_category:
            processed_line_items = st.session_state.get('edited_line_items', parsed_data.get("line_items", []))
            for item in processed_line_items:
                item['category_id'] = category_dict.get(item.get('category'))
                item['category_name'] = item.get('category')
            new_item = {
                "date": expense_date, "vendor": vendor, "description": description, "amount": amount,
                "category_id": category_dict.get(overall_category),
                "receipt_path": receipt_path_for_db, "ocr_text": raw_text if uploaded_receipt else "N/A",
                "gst_amount": gst_amount, "pst_amount": pst_amount, "hst_amount": hst_amount,
                "line_items": processed_line_items
            }
            st.session_state.current_report_items.append(new_item)
            st.success(f"Added: {vendor} - ${amount:.2f} to report '{report_name}'")
        else:
            st.error("Please fill out Vendor, Amount, and Overall Category.")

# Display current report items and final submission button
if st.session_state.current_report_items:
    # ... (this final section remains the same as the last working version) ...
