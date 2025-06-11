import streamlit as st
import fitz  # PyMuPDF
from PIL import Image
import pytesseract
import re
import pandas as pd

CATEGORIES = ['food', 'travel', 'utilities', 'rent', 'entertainment', 'misc']

st.title("📄 Expense Report App with OCR Fallback")

uploaded_file = st.file_uploader("Upload a receipt (PDF or image)", type=["pdf", "png", "jpg", "jpeg"])

if uploaded_file:
    extracted_text = ""

    if uploaded_file.type == "application/pdf":
        doc = fitz.open(stream=uploaded_file.read(), filetype="pdf")
        for page in doc:
            page_text = page.get_text()
            extracted_text += page_text

        # Fallback to OCR if no text found
        if not extracted_text.strip():
            for page in doc:
                pix = page.get_pixmap()
                img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
                extracted_text += pytesseract.image_to_string(img)

    else:
        image = Image.open(uploaded_file)
        extracted_text = pytesseract.image_to_string(image)

    st.subheader("📝 Extracted Text")
    st.text_area("OCR Output", extracted_text, height=200)

    # Parse expenses
    expenses = []
    for line in extracted_text.splitlines():
        line_lower = line.lower()
        for cat in CATEGORIES:
            if cat in line_lower:
                amounts = re.findall(r'\$?\s*([0-9]+(?:\.[0-9]{2})?)', line)
                if amounts:
                    expenses.append({'Category': cat.capitalize(), 'Amount': float(amounts[0])})

    if not expenses:
        amounts = re.findall(r'\$?\s*([0-9]+(?:\.[0-9]{2})?)', extracted_text)
        for amt in amounts:
            expenses.append({'Category': 'Misc', 'Amount': float(amt)})

    if expenses:
        df = pd.DataFrame(expenses)
        st.subheader("📊 Expense Summary")
        st.dataframe(df.groupby("Category").sum().reset_index())
        st.metric("Total Expenses", f"${df['Amount'].sum():.2f}")
    else:
        st.write("No expenses found in the extracted text.")
