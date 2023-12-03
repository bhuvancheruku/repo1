import streamlit as st
from vtapi import VirusTotalAPI
import requests

# Function to check file with VirusTotal API v2
def check_file_virustotal_v2(api_key, file_content):
    url = "https://www.virustotal.com/vtapi/v2/file/scan"
    files = {'file': file_content}
    params = {'apikey': api_key}
    response = requests.post(url, files=files, params=params)
    return response.json()


# Function to check file with VirusTotal API v3
def check_file_virustotal_v3(api_key, file_id):
    # Replace <YOUR_VTAPI_KEY> with your actual VirusTotal API key
    vtapi = VirusTotalAPI("<YOUR_VTAPI_KEY>")
    response = vtapi.get_object("files", file_id)
    return response.to_dict()

# Streamlit UI
st.title("Image Virus Checker with VirusTotal")

# Get the user's VirusTotal API key
api_key = st.text_input("Enter your VirusTotal API key")

# File upload
file = st.file_uploader("Upload an image file", type=["png", "jpg", "jpeg"])

# Input for File ID/Hash for VirusTotal v3 check
file_id = st.text_input("Enter File ID/Hash for VirusTotal v3 check")

if file is not None:
    st.image(file, caption="Uploaded Image", use_column_width=True)

    # Check the file with VirusTotal v2
    # (Keep the VirusTotal v2 check code unchanged)

    # Check the file with VirusTotal v3 using vtapi
    if st.button("Check for Viruses (v3)"):
        if api_key and file_id:  # Checking both API key and file ID/hash are present
            st.write("Checking for viruses using VirusTotal API v3...")
            result_v3 = check_file_virustotal_v3(api_key, file_id)
            st.json(result_v3)
        else:
            st.write("Please enter your VirusTotal API key and File ID/Hash")
