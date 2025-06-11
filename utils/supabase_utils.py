import streamlit as st
from supabase import create_client, Client
import pandas as pd
from datetime import datetime
import os
import json

@st.cache_resource
def init_connection() -> Client:
    try:
        url = st.secrets["supabase"]["url"]
        key = st.secrets["supabase"]["key"]
        return create_client(url, key)
    except KeyError:
        st.error("Supabase credentials not found. Please add your secrets in the Streamlit Cloud dashboard.")
        st.stop()

# --- USER & AUTH FUNCTIONS ---
def fetch_all_users_for_auth():
    supabase = init_connection()
    try:
        response = supabase.table('users').select("username, email, name, hashed_password, role").execute()
        users_data = response.data
        credentials = {"usernames": {}}
        for user in users_data:
            credentials["usernames"][user["username"]] = {"email": user["email"], "name": user["name"], "password": user["hashed_password"], "role": user["role"]}
        return credentials
    except Exception as e:
        st.error(f"Error fetching users: {e}")
        return {"usernames": {}}

def register_user(username, name, email, hashed_password, role='user'):
    supabase = init_connection()
    try:
        user_exists = supabase.table('users').select('id').eq('username', username).execute().data
        if user_exists:
            st.error("Username already taken.")
            return False
        response = supabase.table('users').insert({"username": username, "name": name, "email": email, "hashed_password": hashed_password, "role": role}).execute()
        return len(response.data) > 0
    except Exception as e:
        st.error(f"Error during registration: {e}")
        return False

def get_user_role(username):
    supabase = init_connection()
    try:
        response = supabase.table('users').select('role').eq('username', username).execute()
        return response.data[0].get('role') if response.data else None
    except Exception as e:
        st.error(f"Error fetching user role: {e}")
        return None

def get_user_id_by_username(username):
    supabase = init_connection()
    try:
        response = supabase.table('users').select('id').eq('username', username).execute()
        return response.data[0]['id'] if response.data else None
    except Exception as e:
        st.error(f"Error fetching user ID: {e}")
        return None

def get_all_users():
    supabase = init_connection()
    try:
        response = supabase.table('users').select("id, username, name, email, role, approver_id").execute()
        return pd.DataFrame(response.data)
    except Exception as e:
        st.error(f"Error fetching all users: {e}")
        return pd.DataFrame()

def get_all_approvers():
    supabase = init_connection()
    try:
        response = supabase.table('users').select("id, name").eq('role', 'approver').execute()
        return response.data
    except Exception as e:
        st.error(f"Error fetching approvers: {e}")
        return []

def update_user_details(user_id, role, approver_id):
    supabase = init_connection()
    try:
        supabase.table('users').update({"role": role, "approver_id": approver_id}).eq('id', user_id).execute()
        return True
    except Exception as e:
        st.error(f"Error updating user details: {e}")
        return False

# --- REPORT & EXPENSE FUNCTIONS ---
def upload_receipt(uploaded_file, username):
    supabase = init_connection()
    try:
        file_bytes = uploaded_file.getvalue()
        file_ext = os.path.splitext(uploaded_file.name)[1]
        file_path = f"{username}/{datetime.now().timestamp()}_{datetime.now().strftime('%Y%m%d%H%M%S')}{file_ext}"
        supabase.storage.from_("receipts").upload(file=file_bytes, path=file_path, file_options={"content-type": uploaded_file.type})
        return file_path
    except Exception as e:
        st.error(f"Error uploading receipt: {e}")
        return None

def add_report(user_id, report_name, total_amount):
    supabase = init_connection()
    try:
        response = supabase.table('reports').insert({"user_id": user_id, "report_name": report_name, "submission_date": datetime.now().isoformat(), "total_amount": total_amount, "status": "Submitted"}).execute()
        return response.data[0]['id'] if response.data else None
    except Exception as e:
        st.error(f"Error adding report: {e}")
        return None

def add_expense_item(report_id, expense_date, vendor, description, amount, category_id=None, receipt_path=None, ocr_text=None, gst_amount=None, pst_amount=None, hst_amount=None, line_items=None):
    supabase = init_connection()
    try:
        supabase.table('expenses').insert({
            "report_id": report_id, "expense_date": str(expense_date), "vendor": vendor,
            "description": description, "amount": amount, "category_id": category_id,
            "receipt_path": receipt_path, "ocr_text": ocr_text, "gst_amount": gst_amount,
            "pst_amount": pst_amount, "hst_amount": hst_amount,
            "line_items": json.dumps(line_items) if line_items else None
        }).execute()
        return True
    except Exception as e:
        st.error(f"Error saving an expense item: {e}")
        return False

def get_reports_for_user(user_id):
    supabase = init_connection()
    response = supabase.table('reports').select("*, user:users(name)").eq('user_id', user_id).order('submission_date', desc=True).execute()
    return pd.DataFrame(response.data)

def get_expenses_for_report(report_id):
    supabase = init_connection()
    try:
        response = supabase.table('expenses').select("*, category:categories(name)").eq('report_id', report_id).execute()
        expenses = response.data
        for expense in expenses:
            if expense.get('categories'):
                expense['category_name'] = expense['categories']['name']
                del expense['categories']
            else:
                expense['category_name'] = "N/A"
        return pd.DataFrame(expenses)
    except Exception as e:
        st.error(f"Error fetching expense items: {e}")
        return pd.DataFrame()

def get_receipt_public_url(path):
    supabase = init_connection()
    if not path: return ""
    return supabase.storage.from_('receipts').get_public_url(path)

def get_reports_for_approver(approver_id):
    supabase = init_connection()
    try:
        employees_response = supabase.table('users').select('id').eq('approver_id', approver_id).execute()
        employee_ids = [user['id'] for user in employees_response.data]
        if not employee_ids: return pd.DataFrame()
        reports_response = supabase.table('reports').select("*, user:users(name)").in_('user_id', employee_ids).order('submission_date', desc=True).execute()
        return pd.DataFrame(reports_response.data)
    except Exception as e:
        st.error(f"Error fetching reports for approver: {e}")
        return pd.DataFrame()

def get_all_reports():
    supabase = init_connection()
    try:
        response = supabase.table('reports').select("*, user:users(name)").order('submission_date', desc=True).execute()
        return pd.DataFrame(response.data)
    except Exception as e:
        st.error(f"Error fetching all reports: {e}")
        return pd.DataFrame()

def update_report_status(report_id, status):
    supabase = init_connection()
    try:
        supabase.table('reports').update({"status": status}).eq('id', report_id).execute()
        return True
    except Exception as e:
        st.error(f"Error updating report status: {e}")
        return False

# --- NEW CATEGORY MANAGEMENT FUNCTIONS ---
def get_all_categories():
    """Fetches all expense categories from the database."""
    supabase = init_connection()
    try:
        response = supabase.table('categories').select("id, name, gl_account").order('name', desc=False).execute()
        return response.data
    except Exception as e:
        st.error(f"Error fetching categories: {e}")
        return []

def add_category(name, gl_account):
    """Adds a new category to the database."""
    supabase = init_connection()
    try:
        if supabase.table('categories').select('id', count='exact').eq('name', name).execute().count > 0:
            st.warning(f"Category '{name}' already exists.")
            return False
        supabase.table('categories').insert({"name": name, "gl_account": gl_account}).execute()
        return True
    except Exception as e:
        st.error(f"Error adding category: {e}")
        return False

def update_category(category_id, name, gl_account):
    """Updates an existing category's details."""
    supabase = init_connection()
    try:
        supabase.table('categories').update({"name": name, "gl_account": gl_account}).eq('id', category_id).execute()
        return True
    except Exception as e:
        st.error(f"Error updating category: {e}")
        return False

def delete_category(category_id):
    """Deletes a category from the database."""
    supabase = init_connection()
    try:
        supabase.table('categories').delete().eq('id', category_id).execute()
        return True
    except Exception as e:
        st.error(f"Error deleting category: {e}")
        return False
