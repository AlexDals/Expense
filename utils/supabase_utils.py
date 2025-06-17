import streamlit as st
from supabase import create_client, Client
import pandas as pd
from datetime import datetime
import os
import json
import xml.etree.ElementTree as ET
from xml.dom import minidom

@st.cache_resource
def init_connection() -> Client:
    """Initializes and returns a Supabase client."""
    try:
        url = st.secrets["supabase"]["url"]
        key = st.secrets["supabase"]["key"]
        return create_client(url, key)
    except KeyError:
        st.error("Supabase credentials not found. Please add your secrets in the Streamlit Cloud dashboard.")
        st.stop()

def fetch_all_users_for_auth():
    """Fetches all users from the database for the authenticator."""
    supabase = init_connection()
    try:
        response = supabase.table('users').select("id, username, email, name, hashed_password, role").execute()
        users_data = response.data
        credentials = {"usernames": {}}
        for user in users_data:
            credentials["usernames"][user["username"]] = {"id": user["id"], "email": user["email"], "name": user["name"], "password": user["hashed_password"], "role": user["role"]}
        return credentials
    except Exception as e:
        st.error(f"Error fetching users: {e}"); return {"usernames": {}}

def register_user(username, name, email, hashed_password, role='user'):
    """Registers a new user in the database with a specific role."""
    supabase = init_connection()
    try:
        if supabase.table('users').select('id', count='exact').eq('username', username).execute().count > 0:
            st.error("Username already taken."); return False
        supabase.table('users').insert({"username": username, "name": name, "email": email, "hashed_password": hashed_password, "role": role}).execute()
        return True
    except Exception as e:
        st.error(f"Error during registration: {e}"); return False

def get_user_role(username):
    """Fetches just the role for a specific username upon login."""
    supabase = init_connection()
    try:
        response = supabase.table('users').select('role').eq('username', username).execute()
        return response.data[0].get('role') if response.data else None
    except Exception as e:
        st.error(f"Error fetching user role: {e}"); return None

def get_all_users():
    """Fetches all user data for the management page."""
    supabase = init_connection()
    try:
        response = supabase.table('users').select("id, username, name, email, role, approver_id, department").execute()
        return pd.DataFrame(response.data)
    except Exception as e:
        st.error(f"Error fetching all users: {e}"); return pd.DataFrame()

def get_all_approvers():
    """Fetches all users with the 'approver' OR 'admin' role."""
    supabase = init_connection()
    try:
        response = supabase.table('users').select("id, name").in_('role', ['approver', 'admin']).execute()
        return response.data
    except Exception as e:
        st.error(f"Error fetching approvers: {e}"); return []

def update_user_details(user_id, role, approver_id, department):
    """Updates a user's role, assigned approver, and department."""
    supabase = init_connection()
    try:
        supabase.table('users').update({"role": role, "approver_id": approver_id, "department": department}).eq('id', user_id).execute()
        return True
    except Exception as e:
        st.error(f"Error updating user details: {e}"); return False

def add_report(user_id, report_name, total_amount):
    """Adds a new report header to the database."""
    supabase = init_connection()
    try:
        response = supabase.table('reports').insert({"user_id": user_id, "report_name": report_name, "submission_date": datetime.now().isoformat(), "total_amount": total_amount, "status": "Submitted"}).execute()
        return response.data[0]['id'] if response.data else None
    except Exception as e:
        st.error(f"Error adding report: {e}"); return None

def add_expense_item(report_id, expense_date, vendor, description, amount, currency='CAD', category_id=None, receipt_path=None, ocr_text=None, gst_amount=None, pst_amount=None, hst_amount=None, line_items=None):
    """Adds a new expense item to a report."""
    supabase = init_connection()
    try:
        supabase.table('expenses').insert({
            "report_id": report_id, "expense_date": str(expense_date), "vendor": vendor,
            "description": description, "amount": amount, "category_id": category_id,
            "receipt_path": receipt_path, "ocr_text": ocr_text, "gst_amount": gst_amount,
            "pst_amount": pst_amount, "hst_amount": hst_amount,
            "line_items": json.dumps(line_items) if line_items else None,
            "currency": currency
        }).execute()
        return True
    except Exception as e:
        st.error(f"Error saving an expense item: {e}"); return False

def update_expense_item(expense_id, updates: dict):
    """Updates an existing expense item with a dictionary of changes."""
    supabase = init_connection()
    try:
        supabase.table('expenses').update(updates).eq('id', expense_id).execute()
        return True
    except Exception as e:
        st.error(f"Error updating expense item: {e}"); return False

def get_reports_for_user(user_id):
    """Fetches all report summaries for a specific user."""
    supabase = init_connection()
    response = supabase.table('reports').select("*, user:users!left(name)").eq('user_id', user_id).order('submission_date', desc=True).execute()
    return pd.DataFrame(response.data)

def get_expenses_for_report(report_id):
    """Fetches all expense items for a report, including the category name."""
    supabase = init_connection()
    try:
        response = supabase.table('expenses').select("*, category:categories!left(name)").eq('report_id', report_id).execute()
        expenses = response.data
        for expense in expenses:
            if expense.get('category') and isinstance(expense['category'], dict):
                expense['category_name'] = expense['category'].get('name')
            else:
                expense['category_name'] = None
            expense.pop('category', None)
        return pd.DataFrame(expenses)
    except Exception as e:
        st.error(f"Error fetching expense items: {e}"); return pd.DataFrame()

def get_receipt_public_url(path: str):
    """Gets the public URL for a receipt from its storage path."""
    supabase = init_connection()
    if not path: return ""
    return supabase.storage.from_('receipts').get_public_url(path)

def get_reports_for_approver(approver_id):
    """Fetches reports for an approver based on department."""
    supabase = init_connection()
    try:
        approver_dept_response = supabase.table('users').select('department').eq('id', approver_id).maybe_single().execute()
        if not approver_dept_response.data or not approver_dept_response.data.get('department'):
            return pd.DataFrame()
        approver_department = approver_dept_response.data['department']
        employees_response = supabase.table('users').select('id').eq('department', approver_department).neq('id', approver_id).execute()
        employee_ids = [user['id'] for user in employees_response.data]
        if not employee_ids: return pd.DataFrame()
        reports_response = supabase.table('reports').select("*, user:users!left(name)").in_('user_id', employee_ids).order('submission_date', desc=True).execute()
        return pd.DataFrame(reports_response.data)
    except Exception as e:
        st.error(f"Error fetching reports for approver: {e}"); return pd.DataFrame()

def get_all_reports():
    """Fetches all reports for admin view."""
    supabase = init_connection()
    try:
        response = supabase.table('reports').select("*, user:users!left(name)").order('submission_date', desc=True).execute()
        return pd.DataFrame(response.data)
    except Exception as e:
        st.error(f"Error fetching all reports: {e}"); return pd.DataFrame()

def update_report_status(report_id, status, comment=None):
    """Updates the status of a specific report and optionally adds a comment."""
    supabase = init_connection()
    try:
        updates = {"status": status}
        if comment: updates["approver_comment"] = comment
        supabase.table('reports').update(updates).eq('id', report_id).execute()
        return True
    except Exception as e:
        st.error(f"Error updating report status: {e}"); return False

def get_all_categories():
    """Fetches all expense categories from the database."""
    supabase = init_connection()
    try:
        response = supabase.table('categories').select("id, name, gl_account").order('name', desc=False).execute()
        return response.data
    except Exception as e:
        st.error(f"Error fetching categories: {e}"); return []

def add_category(name, gl_account):
    """Adds a new category to the database."""
    supabase = init_connection()
    try:
        if supabase.table('categories').select('id', count='exact').eq('name', name).execute().count > 0:
            st.warning(f"Category '{name}' already exists."); return False
        supabase.table('categories').insert({"name": name, "gl_account": gl_account}).execute()
        return True
    except Exception as e:
        st.error(f"Error adding category: {e}"); return False

def update_category(category_id, name, gl_account):
    """Updates an existing category's details."""
    supabase = init_connection()
    try:
        supabase.table('categories').update({"name": name, "gl_account": gl_account}).eq('id', category_id).execute()
        return True
    except Exception as e:
        st.error(f"Error updating category: {e}"); return False

def delete_category(category_id):
    """Deletes a category from the database."""
    supabase = init_connection()
    try:
        supabase.table('categories').delete().eq('id', category_id).execute()
        return True
    except Exception as e:
        st.error(f"Error deleting category: {e}"); return False

def generate_report_xml(report_data: pd.Series, expenses_data: pd.DataFrame, submitter_name: str):
    """Generates an XML string for a given report in the specified format."""
    def create_sub_element(parent, tag, text, attributes=None):
        element = ET.SubElement(parent, tag, attrib=attributes or {})
        element.text = str(text) if text is not None and pd.notna(text) else ""
        return element
        
    all_categories = get_all_categories()
    category_id_to_gl_map = {cat['id']: cat['gl_account'] for cat in all_categories}

    record = ET.Element("Record", {"SystemDBVersion": "3676", "ExportFileFormatVersion": "1.002", "ExportDate": datetime.now().strftime("%Y-%m-%d"), "DataObjectID": "{02E10F25-EDA3-4A1C-AF1C-741067C309B1}", "AllowDataSetEvents": "0"})
    header = ET.SubElement(record, "Header", {"Table": "PurcHdr", "TableType": "1"})
    
    default_values_hdr = ET.SubElement(header, "DefaultValues")
    create_sub_element(default_values_hdr, "Member", datetime.now().strftime("%m/%d/%Y")).set("Name", "PurcDate")
    # Add other hard-coded default members as needed...

    rows_header = ET.SubElement(header, "Rows")
    row_header = ET.SubElement(rows_header, "Row")
    
    first_expense = expenses_data.iloc[0] if not expenses_data.empty else {}
    currency = first_expense.get('currency', 'CAD') if pd.notna(first_expense.get('currency')) else 'CAD'

    create_sub_element(row_header, "ExSuppId", first_expense.get('vendor', 'N/A'), {"MemberName": "SuppId"})
    create_sub_element(row_header, "PurcDate", str(report_data.get('submission_date', ''))[:10])
    create_sub_element(row_header, "DocNo", report_data.get('report_name', ''))
    create_sub_element(row_header, "ExTermId", "N/A", {"MemberName": "Descr"})
    create_sub_element(row_header, "Remarks", report_data.get('report_name', ''))
    create_sub_element(row_header, "ExchangeRate", "1")
    create_sub_element(row_header, "PurcFrom", first_expense.get('vendor', 'N/A'))
    total_tax = expenses_data[['gst_amount', 'pst_amount', 'hst_amount']].sum().sum()
    create_sub_element(row_header, "TaxAmnt", f"{total_tax:.2f}")
    create_sub_element(row_header, "TotAmnt", f"{report_data.get('total_amount', 0):.2f}")
    create_sub_element(row_header, "ExCurrencyId", currency, {"MemberName": "CurrencyCode"})
    create_sub_element(row_header, "ExPmtMethId", "Check", {"MemberName": "PmtMeth"})
    create_sub_element(row_header, "ShipTo", "") # Leave empty as requested

    details = ET.SubElement(record, "Details")
    for _, expense_row in expenses_data.iterrows():
        detail = ET.SubElement(details, "Detail", {"Table": "PurcDet", "TableType": "2"})
        rows_detail = ET.SubElement(detail, "Rows")
        
        line_items_str = expense_row.get('line_items')
        line_items = []
        if line_items_str and isinstance(line_items_str, str):
            try: line_items = json.loads(line_items_str)
            except json.JSONDecodeError: line_items = []
        if not line_items:
            line_items = [{"description": expense_row.get('description'), "price": expense_row.get('amount'), "category_id": expense_row.get('category_id')}]

        for item in line_items:
            if item and item.get('price') is not None:
                row_detail = ET.SubElement(rows_detail, "Row")
                item_category_id = item.get('category_id')
                gl_account = category_id_to_gl_map.get(item_category_id)
                create_sub_element(row_detail, "ExPurcAcctId", gl_account, {"MemberName": "GLAcctId"})
                create_sub_element(row_detail, "Qty", "1")
                create_sub_element(row_detail, "UnitPrice", f"{item.get('price', 0):.2f}")
    
    rough_string = ET.tostring(record, 'utf-8')
    reparsed = minidom.parseString(rough_string)
    return reparsed.toprettyxml(indent="  ")
