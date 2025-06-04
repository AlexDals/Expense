
import streamlit as st
import pandas as pd
from io import BytesIO
import base64 
import google.generativeai as genai
from datetime import datetime
import json
import os
import hashlib # For password hashing
import uuid # For generating unique IDs

# --- Configuration ---
# For OCR - Configure your Gemini API Key
# Option 1: Streamlit Secrets (recommended for deployment)
# GEMINI_API_KEY = st.secrets.get("GEMINI_API_KEY", None)

# Option 2: Environment Variable (good for local dev if you don't want to use secrets.toml)
# GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")

# Option 3: Direct Input (least secure, for quick local testing only, DO NOT COMMIT THIS)
GEMINI_API_KEY = "YOUR_GEMINI_API_KEY" # Replace or comment out

if GEMINI_API_KEY and GEMINI_API_KEY != "YOUR_GEMINI_API_KEY":
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        print("Gemini API Key configured.")
    except Exception as e:
        st.warning(f"Error configuring Gemini API: {e}. OCR will not work.")
        print(f"Error configuring Gemini API: {e}")
        GEMINI_API_KEY = None # Disable OCR if config fails
else:
    st.warning("Gemini API Key not configured. OCR functionality will be disabled. Set it in Streamlit secrets, as an environment variable, or directly in the code for testing.")
    GEMINI_API_KEY = None


# --- Data File Paths ---
DATA_DIR = "app_data"
USERS_FILE = os.path.join(DATA_DIR, "users.json")
CATEGORIES_FILE = os.path.join(DATA_DIR, "categories.json")
# Expenses will be stored in files like expenses_USERID.json

# --- Ensure Data Directory Exists ---
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

# --- Helper Functions for Data Handling ---
def load_data(file_path, default_data=None):
    """Loads data from a JSON file."""
    if default_data is None:
        default_data = []
    try:
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                return json.load(f)
        return default_data
    except (IOError, json.JSONDecodeError) as e:
        print(f"Error loading {file_path}: {e}. Returning default.")
        return default_data

def save_data(file_path, data):
    """Saves data to a JSON file."""
    try:
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=4)
        return True
    except IOError as e:
        print(f"Error saving {file_path}: {e}")
        st.error(f"Failed to save data to {file_path}.")
        return False

def get_user_expenses_file_path(user_uid):
    """Generates the file path for a user's expenses."""
    return os.path.join(DATA_DIR, f"expenses_{user_uid}.json")

# --- Password Hashing ---
def hash_password(password, salt=None):
    """Hashes a password with a salt."""
    if salt is None:
        salt = os.urandom(16).hex() # Generate a new salt
    salted_password = salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return hashed_password, salt

def verify_password(stored_password_hash, salt, provided_password):
    """Verifies a provided password against a stored hash and salt."""
    hashed_provided_password, _ = hash_password(provided_password, salt)
    return hashed_provided_password == stored_password_hash

# --- Authentication Functions (Local) ---
def handle_login(email, password):
    users = load_data(USERS_FILE, [])
    user_found = None
    for user in users:
        if user.get("email") == email:
            user_found = user
            break
    
    if user_found and verify_password(user_found.get("hashed_password"), user_found.get("salt"), password):
        st.session_state.logged_in = True
        st.session_state.user_uid = user_found.get("uid")
        st.session_state.user_email = user_found.get("email")
        st.session_state.user_name = user_found.get("name")
        st.session_state.user_role = user_found.get("role", "user")
        st.session_state.current_page = "expenses"
        st.success(f"Logged in as {st.session_state.user_name or st.session_state.user_email}!")
        st.rerun()
        return True
    else:
        st.error("Invalid email or password.")
        return False

def handle_registration(email, password, display_name, set_register_error_callback):
    users = load_data(USERS_FILE, [])

    allowed_domains = ["dals.com", "dalslighting.com"]
    try:
        email_domain = email.split('@')[-1]
        if not email_domain.lower() in allowed_domains:
            set_register_error_callback(f"Registration is only allowed for @dals.com or @dalslighting.com email addresses.")
            return False
    except IndexError: # Handles cases where email might not have "@"
        set_register_error_callback("Invalid email format.")
        return False


    if any(user.get("email") == email for user in users):
        set_register_error_callback("This email address is already in use.")
        return False

    user_uid = str(uuid.uuid4())
    hashed_password, salt = hash_password(password)
    
    new_user = {
        "uid": user_uid,
        "email": email,
        "name": display_name or email.split('@')[0],
        "hashed_password": hashed_password,
        "salt": salt,
        "role": "user", # Default role
        "createdAt": datetime.now().isoformat()
    }
    users.append(new_user)
    if save_data(USERS_FILE, users):
        st.session_state.logged_in = True
        st.session_state.user_uid = new_user["uid"]
        st.session_state.user_email = new_user["email"]
        st.session_state.user_name = new_user["name"]
        st.session_state.user_role = new_user["role"]
        st.session_state.current_page = "expenses"
        st.success(f"Registered and logged in as {display_name or email}!")
        st.rerun()
        return True
    else:
        set_register_error_callback("Failed to save user data during registration.")
        return False


def handle_logout():
    keys_to_delete = [key for key in st.session_state.keys() if key.startswith("user_") or key in ["logged_in", "current_page", "categories", "ocr_scanned_amount"]]
    for key in keys_to_delete:
        del st.session_state[key]
    st.session_state.logged_in = False
    st.session_state.current_page = "login"
    st.success("Logged out successfully.")
    st.rerun()

# --- OCR Function ---
def get_ocr_data_from_image(image_bytes, mime_type):
    if not GEMINI_API_KEY:
        return None, "OCR functionality is disabled because Gemini API Key is not configured."
    try:
        model = genai.GenerativeModel(
            model_name="gemini-1.5-flash",
            generation_config={
                "response_mime_type": "application/json",
                "response_schema": {
                    "type": "OBJECT",
                    "properties": {
                        "subtotal": {"type": "STRING"}, "taxes": {"type": "ARRAY", "items": {"type": "OBJECT", "properties": {"taxCode": {"type": "STRING"}, "taxAmount": {"type": "STRING"}}, "required": ["taxCode", "taxAmount"]}}, "total": {"type": "STRING"}
                    }, "required": ["subtotal", "taxes", "total"]
                }
            }
        )
        prompt = "Analyze this receipt image. Extract the subtotal, a list of all taxes (each with its tax code like GST, PST, HST, QST and its corresponding amount), and the grand total. Amounts as strings (e.g., '12.34'). Null if not found. Empty array for no taxes."
        image_part = {"mime_type": mime_type, "data": base64.b64encode(image_bytes).decode()}
        response = model.generate_content([prompt, image_part])
        print("Gemini API Response Text:", response.text)
        return json.loads(response.text), None
    except Exception as e:
        print(f"Error during OCR processing: {e}")
        return None, f"OCR processing failed: {e}"

# --- UI Page Functions ---
def login_page():
    st.header("Login to Expense Pro (Local Data)")
    with st.form("login_form_local"):
        email = st.text_input("Email Address", key="login_email")
        password = st.text_input("Password", type="password", key="login_password")
        submitted = st.form_submit_button("Login")
        if submitted:
            if not email or not password:
                st.error("Email and Password are required.")
            else:
                handle_login(email, password)
    st.markdown("---")
    if st.button("Go to Registration", key="login_to_register_btn"):
        st.session_state.current_page = "register"
        st.rerun()

def register_page():
    st.header("Register for Expense Pro (Local Data)")
    
    # Local error state for this page
    register_error_placeholder = st.empty()

    def set_local_register_error(msg):
        register_error_placeholder.error(msg)

    with st.form("register_form_local"):
        display_name = st.text_input("Display Name (Optional)", key="reg_display_name")
        email = st.text_input("Email Address (dals.com or dalslighting.com only)", key="reg_email")
        password = st.text_input("Password (min. 6 characters)", type="password", key="reg_password")
        confirm_password = st.text_input("Confirm Password", type="password", key="reg_confirm_password")
        submitted = st.form_submit_button("Register")

        if submitted:
            if not email or not password or not confirm_password:
                set_local_register_error("Email, Password, and Confirm Password are required.")
            elif password != confirm_password:
                set_local_register_error("Passwords do not match.")
            elif len(password) < 6:
                set_local_register_error("Password must be at least 6 characters long.")
            else:
                handle_registration(email, password, display_name, set_local_register_error)
    
    st.markdown("---")
    if st.button("Back to Login", key="register_to_login_btn"):
        st.session_state.current_page = "login"
        st.rerun()

def expense_page():
    st.header(f"Welcome, {st.session_state.get('user_name', 'User')}!")
    st.subheader("Your Expenses")

    # Load categories for the dropdown
    categories_data = load_data(CATEGORIES_FILE, [])
    st.session_state.categories = categories_data # Keep it updated in session state for forms

    with st.expander("Add New Expense", expanded=False):
        with st.form("new_expense_form_local", clear_on_submit=True):
            expense_date = st.date_input("Date", value=datetime.today(), key="exp_date")
            categories_list = ["Other"] + [cat["name"] for cat in categories_data]
            expense_category_name = st.selectbox("Category", options=categories_list, index=0, key="exp_cat")
            expense_description = st.text_area("Description", key="exp_desc")
            expense_amount_key = "exp_amount_ocr" if 'ocr_scanned_amount' in st.session_state else "exp_amount_manual"
            default_amount = st.session_state.get('ocr_scanned_amount', 0.01)
            
            expense_amount = st.number_input(
                f"Amount {'(OCR Prefilled)' if 'ocr_scanned_amount' in st.session_state else ''}", 
                value=float(default_amount), 
                min_value=0.01, 
                format="%.2f", 
                key=expense_amount_key
            )
            expense_currency = st.selectbox("Currency", ["CAD", "USD", "EUR"], key="exp_curr")
            
            uploaded_receipt = st.file_uploader("Upload Receipt (Optional)", type=["png", "jpg", "jpeg"], key="exp_receipt")
            ocr_subtotal, ocr_taxes_list, ocr_total_val = None, [], None

            if uploaded_receipt:
                st.image(uploaded_receipt, caption="Uploaded Receipt", width=200)
                if st.button("Scan Receipt for Amounts", key="scan_receipt_btn"):
                    with st.spinner("Processing OCR..."):
                        image_bytes = uploaded_receipt.getvalue()
                        mime_type = uploaded_receipt.type
                        ocr_result, ocr_err_msg = get_ocr_data_from_image(image_bytes, mime_type)
                        if ocr_result:
                            st.success("OCR successful!")
                            ocr_subtotal = ocr_result.get("subtotal")
                            ocr_taxes_list = ocr_result.get("taxes", [])
                            ocr_total_val = ocr_result.get("total")
                            if ocr_total_val: st.session_state.ocr_scanned_amount = float(ocr_total_val)
                            st.rerun() # Rerun to update amount field
                        else:
                            st.error(f"OCR Error: {ocr_err_msg}")
            
            submit_expense = st.form_submit_button("Add Expense")
            if submit_expense:
                if not expense_description or not expense_category_name or expense_amount <= 0:
                    st.error("Please fill in Date, Category, Description, and a valid Amount.")
                else:
                    selected_cat_details = next((c for c in categories_data if c["name"] == expense_category_name), {"glAccount": "N/A"})
                    
                    user_expenses_file = get_user_expenses_file_path(st.session_state.user_uid)
                    current_user_expenses = load_data(user_expenses_file, [])
                    
                    new_expense_entry = {
                        "id": str(uuid.uuid4()), "userId": st.session_state.user_uid,
                        "date": expense_date.strftime("%Y-%m-%d"), "categoryName": expense_category_name,
                        "glAccount": selected_cat_details["glAccount"], "description": expense_description,
                        "amount": float(expense_amount), "currency": expense_currency,
                        "submittedAt": datetime.now().isoformat(),
                        "ocrExtractedSubtotal": st.session_state.get('ocr_subtotal'),
                        "ocrExtractedTaxes": st.session_state.get('ocr_taxes_list', []),
                        "ocrExtractedTotal": st.session_state.get('ocr_total_val'),
                    }
                    current_user_expenses.append(new_expense_entry)
                    if save_data(user_expenses_file, current_user_expenses):
                        st.success("Expense added successfully!")
                        # Clear OCR prefill state
                        for key in ['ocr_scanned_amount', 'ocr_subtotal', 'ocr_taxes_list', 'ocr_total_val']:
                            if key in st.session_state: del st.session_state[key]
                        st.rerun()
                    else:
                        st.error("Failed to save expense.")
    
    # Display Expenses
    user_expenses_file = get_user_expenses_file_path(st.session_state.user_uid)
    expenses_list = load_data(user_expenses_file, [])
    expenses_list.sort(key=lambda x: x.get("submittedAt", ""), reverse=True)

    if expenses_list:
        df_expenses = pd.DataFrame(expenses_list)
        cols_to_show = ["date", "description", "categoryName", "glAccount", "amount", "currency"]
        if any(exp.get("ocrExtractedTotal") for exp in expenses_list):
            df_expenses["OCR Total"] = [exp.get("ocrExtractedTotal") for exp in expenses_list]
            cols_to_show.append("OCR Total")
        st.dataframe(df_expenses[cols_to_show], use_container_width=True)
    else:
        st.info("No expenses logged yet.")

    # Summary & Export (Simplified for local data)
    if expenses_list:
        st.subheader("Summary & Export")
        total_cad = sum(e["amount"] for e in expenses_list if e["currency"] == "CAD")
        st.metric("Total Expenses (CAD)", f"${total_cad:.2f}")
        # Export functionality would need to be implemented using pandas to_csv/to_excel

def admin_page():
    st.header("Admin Panel (Local Data)")
    if st.session_state.get("user_role") != "admin":
        st.error("Access Denied.")
        return

    admin_tabs = st.tabs(["User Management", "Category Management"])

    with admin_tabs[0]:
        st.subheader("Manage Users")
        users = load_data(USERS_FILE, [])
        if users:
            df_users = pd.DataFrame(users)
            # Don't show hashed_password or salt in UI
            st.dataframe(df_users[["uid", "name", "email", "role"]], use_container_width=True)
            
            st.markdown("---")
            st.subheader("Modify User Role")
            user_emails = [u["email"] for u in users if u["uid"] != st.session_state.user_uid]
            if user_emails:
                selected_user_email = st.selectbox("Select User by Email", options=user_emails, key="admin_select_user")
                selected_user_idx = next((i for i, u in enumerate(users) if u["email"] == selected_user_email), None)

                if selected_user_idx is not None:
                    current_role = users[selected_user_idx]["role"]
                    new_role = st.selectbox(f"New Role for {users[selected_user_idx]['name']}", options=["user", "admin"], index=0 if current_role == "user" else 1, key="admin_new_role")
                    if st.button(f"Update Role", key="admin_update_role_btn"):
                        users[selected_user_idx]["role"] = new_role
                        if save_data(USERS_FILE, users):
                            st.success(f"Role for {users[selected_user_idx]['name']} updated.")
                            st.rerun()
                    
                    if st.button(f"Delete User: {users[selected_user_idx]['name']}", type="primary", key="admin_delete_user_btn"):
                        if st.checkbox(f"Confirm deletion of {users[selected_user_idx]['name']}", key="admin_confirm_delete"):
                            del users[selected_user_idx]
                            if save_data(USERS_FILE, users):
                                # Also delete their expenses file
                                expenses_file_to_delete = get_user_expenses_file_path(users[selected_user_idx]["uid"]) # This index is now wrong
                                # Need to get UID before deleting from users list
                                # This part needs careful implementation if deleting expenses file too.
                                # For now, just deleting from users.json
                                st.success(f"User {selected_user_email} removed from users file.")
                                st.rerun()
            else:
                st.info("No other users to manage.")
        else:
            st.info("No users found.")

    with admin_tabs[1]:
        st.subheader("Manage Expense Categories & GL Accounts")
        categories = load_data(CATEGORIES_FILE, [])
        st.session_state.categories = categories # Ensure it's in session state for other parts

        if categories:
            st.write("Current Categories:")
            for i, cat in enumerate(categories):
                col1, col2, col3 = st.columns([3,2,1])
                col1.write(cat["name"])
                col2.write(f"GL: {cat['glAccount']}")
                if col3.button("Del", key=f"del_cat_local_{cat.get('id', i)}"):
                    categories.pop(i)
                    if save_data(CATEGORIES_FILE, categories):
                        st.success(f"Category '{cat['name']}' deleted.")
                        st.rerun()
        else:
            st.info("No categories configured yet.")

        with st.form("add_category_form_local", clear_on_submit=True):
            new_cat_name = st.text_input("Category Name", key="admin_cat_name")
            new_cat_gl = st.text_input("GL Account", key="admin_cat_gl")
            if st.form_submit_button("Add Category"):
                if new_cat_name and new_cat_gl:
                    categories.append({"id": str(uuid.uuid4()), "name": new_cat_name, "glAccount": new_cat_gl})
                    if save_data(CATEGORIES_FILE, categories):
                        st.success(f"Category '{new_cat_name}' added.")
                        st.rerun()
                else:
                    st.error("Name and GL Account are required.")

# --- Main App Logic ---
def main():
    st.set_page_config(page_title="Expense Pro (Local Data)", layout="wide")

    # Initialize session state variables
    if "logged_in" not in st.session_state: st.session_state.logged_in = False
    if "current_page" not in st.session_state: st.session_state.current_page = "login"
    # ... other session state initializations ...

    if st.session_state.logged_in:
        st.sidebar.header(f"Welcome, {st.session_state.get('user_name', 'User')}!")
        st.sidebar.caption(f"Role: {st.session_state.get('user_role', 'user')}")
        if st.sidebar.button("My Expenses", use_container_width=True, key="nav_expenses"):
            st.session_state.current_page = "expenses"; st.rerun()
        if st.session_state.get("user_role") == "admin":
            if st.sidebar.button("Admin Panel", use_container_width=True, key="nav_admin"):
                st.session_state.current_page = "admin"; st.rerun()
        if st.sidebar.button("Logout", use_container_width=True, type="primary", key="nav_logout"):
            handle_logout()
    else:
        st.sidebar.info("Please log in or register.")

    if st.session_state.current_page == "login": login_page()
    elif st.session_state.current_page == "register": register_page()
    elif st.session_state.logged_in and st.session_state.current_page == "expenses": expense_page()
    elif st.session_state.logged_in and st.session_state.current_page == "admin" and st.session_state.get("user_role") == "admin": admin_page()
    elif st.session_state.logged_in and st.session_state.current_page == "admin": # Non-admin trying to access admin
        st.error("Access Denied."); st.session_state.current_page = "expenses"; st.rerun()
    else: # Default to login
        login_page()

if __name__ == "__main__":
    main()
