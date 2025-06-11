import sqlite3
import pandas as pd
import streamlit as st # Import Streamlit to access its filesystem

# On Streamlit Cloud, the database will be created in the root of your app's deployed files.
# It will persist as long as your app instance is running.
# IMPORTANT: Streamlit Cloud has an ephemeral filesystem.
# This means the SQLite file MIGHT be lost if your app instance sleeps due to inactivity
# or if you redeploy. For persistent storage, consider a cloud-based database
# (e.g., Streamlit's upcoming native DB, Firebase, Supabase, Heroku Postgres).
DB_NAME = 'expense_reports.db'

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        report_name TEXT,
        submission_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        total_amount REAL
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS expenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        report_id INTEGER NOT NULL,
        expense_date TEXT,
        vendor TEXT,
        description TEXT,
        amount REAL,
        receipt_image BLOB,
        ocr_text TEXT,
        FOREIGN KEY (report_id) REFERENCES reports (id)
    )
    ''')
    conn.commit()
    conn.close()

def add_report(username, report_name, total_amount):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO reports (username, report_name, total_amount) VALUES (?, ?, ?)",
                   (username, report_name, total_amount))
    report_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return report_id

def add_expense_item(report_id, expense_date, vendor, description, amount, receipt_image_bytes=None, ocr_text=None):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
    INSERT INTO expenses (report_id, expense_date, vendor, description, amount, receipt_image, ocr_text)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (report_id, str(expense_date), vendor, description, amount, receipt_image_bytes, ocr_text))
    conn.commit()
    conn.close()

def get_reports_for_user(username):
    conn = sqlite3.connect(DB_NAME)
    query = "SELECT id, report_name, submission_date, total_amount FROM reports WHERE username = ? ORDER BY submission_date DESC"
    df = pd.read_sql_query(query, conn, params=(username,))
    conn.close()
    return df

def get_expenses_for_report(report_id):
    conn = sqlite3.connect(DB_NAME)
    query = "SELECT expense_date, vendor, description, amount, ocr_text FROM expenses WHERE report_id = ?"
    df = pd.read_sql_query(query, conn, params=(report_id,))
    conn.close()
    return df

def get_all_expenses_for_user_for_export(username):
    conn = sqlite3.connect(DB_NAME)
    query = """
    SELECT r.report_name, r.submission_date, e.expense_date, e.vendor, e.description, e.amount
    FROM reports r
    JOIN expenses e ON r.id = e.report_id
    WHERE r.username = ?
    ORDER BY r.submission_date DESC, e.expense_date DESC
    """
    df = pd.read_sql_query(query, conn, params=(username,))
    conn.close()
    return df

# Initialize the database and tables if they don't exist when this module is first imported
init_db()
