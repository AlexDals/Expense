import streamlit as st
from google.cloud import vision
import google.generativeai as genai
import json
import fitz  # PyMuPDF for PDF handling
import io
from PIL import Image

# --- GOOGLE VISION API SETUP (for OCR) ---
@st.cache_resource
def get_vision_client():
    """Initializes and returns a Google Vision API client."""
    try:
        credentials_dict = dict(st.secrets.google_credentials)
        client = vision.ImageAnnotatorClient.from_service_account_info(credentials_dict)
        return client
    except Exception as e:
        st.error(f"Could not initialize Google Vision API client: {e}")
        st.stop()

# --- GEMINI API SETUP (for Parsing) ---
@st.cache_resource
def get_gemini_client():
    """Initializes and returns a Gemini API client."""
    try:
        api_key = st.secrets.gemini.api_key
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-1.5-flash')
        return model
    except Exception as e:
        st.error(f"Could not initialize Gemini API client: {e}")
        st.stop()

# --- STEP 1: TEXT EXTRACTION ---
def extract_text_from_file(uploaded_file):
    """
    Extracts text from an image or PDF file using Google Cloud Vision AI.
    If the file is a PDF, it converts each page to an image before sending.
    """
    client = get_vision_client()
    file_bytes = uploaded_file.getvalue()
    mime_type = uploaded_file.type
    
    try:
        if mime_type == "application/pdf":
            full_text = ""
            with fitz.open(stream=file_bytes, filetype="pdf") as doc:
                for page_num, page in enumerate(doc):
                    pix = page.get_pixmap(dpi=300)
                    img_bytes = pix.tobytes("png")
                    image = vision.Image(content=img_bytes)
                    response = client.document_text_detection(image=image)
                    if response.error.message:
                        raise Exception(f"Google Vision API error on page {page_num+1}: {response.error.message}")
                    full_text += response.full_text_annotation.text + "\n"
            return full_text
        elif mime_type in ["image/png", "image/jpeg", "image/jpg"]:
            image = vision.Image(content=file_bytes)
            response = client.document_text_detection(image=image)
            if response.error.message:
                raise Exception(response.error.message)
            return response.full_text_annotation.text
        else:
            return "Unsupported file type."
    except Exception as e:
        return f"Error calling Google Vision API: {str(e)}"

# --- STEP 2: AI-POWERED PARSING ---
def parse_text_with_gemini(ocr_text: str):
    """Uses Gemini to parse raw OCR text into a structured dictionary."""
    model = get_gemini_client()
    
    prompt = f"""
    You are an expert expense analyst. Your task is to accurately extract structured information from the provided OCR text of a receipt.

    INSTRUCTIONS:
    1.  Analyze the entire receipt text provided below.
    2.  Extract the following fields: vendor, date, total_amount, gst_amount, pst_amount, hst_amount, and all distinct line_items.
    3.  For 'vendor', find the main store or company name. It is often the first capitalized line.
    4.  For 'date', find the primary date of the transaction in YYYY-MM-DD format if possible.
    5.  For 'total_amount', find the final grand total paid, usually labeled "Total".
    6.  For 'gst_amount' and 'pst_amount', find the amounts explicitly labeled with "GST"/"TPS" and "PST"/"TVQ" respectively. If "HST" is present, use the 'hst_amount' field.
    7.  For 'line_items', extract all individual products or services. Each line item must have a 'description' and a 'price'. Do not include taxes, subtotals, or totals as line items.
    8.  Return the data as a single, valid JSON object. Do not include any text, markdown, or formatting outside of the JSON object. If a value is not found, set it to 0.0 for numerical fields and null for text fields. The line_items must be an array of objects.

    RECEIPT TEXT:
    ---
    {ocr_text}
    ---

    JSON OUTPUT:
    """
    
    try:
        generation_config = genai.GenerationConfig(response_mime_type="application/json")
        response = model.generate_content(prompt, generation_config=generation_config)
        
        parsed_data = json.loads(response.text)
        # Ensure all keys exist to prevent errors in the Streamlit UI
        for key in ["vendor", "date", "total_amount", "gst_amount", "pst_amount", "hst_amount", "line_items"]:
            if key not in parsed_data:
                if key == "line_items":
                    parsed_data[key] = []
                elif "amount" in key:
                    parsed_data[key] = 0.0
                else:
                    parsed_data[key] = None
        return parsed_data

    except Exception as e:
        st.error(f"Error parsing receipt with AI model: {e}")
        return {"vendor": "Error parsing", "date": None, "total_amount": 0.0, "gst_amount": 0.0, "pst_amount": 0.0, "hst_amount": 0.0, "line_items": []}

# --- Main Entry Point Function ---
def extract_and_parse_file(uploaded_file):
    """Main pipeline function using Google Vision for OCR and Gemini for parsing."""
    try:
        raw_text = extract_text_from_file(uploaded_file)
        if "Error" in raw_text or "Unsupported" in raw_text:
             return raw_text, {"error": raw_text}
        
        parsed_data = parse_text_with_gemini(raw_text)
        return raw_text, parsed_data
        
    except Exception as e:
        error_message = f"A critical error occurred: {str(e)}"
        return error_message, {"error": error_message}
