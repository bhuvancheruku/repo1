import streamlit as st
import requests

# Function to check file with VirusTotal API v2
def check_file_virustotal_v2(api_key, file_content):
    url = "https://www.virustotal.com/vtapi/v2/file/scan"
    files = {'file': file_content}
    params = {'x-apikey': api_key}
    response = requests.post(url, files=files, params=params)
    return response.json()

# Function to check file with VirusTotal API v3
def check_file_virustotal_v3(api_key, file_id):
    url = f"https://www.virustotal.com/api/v3/files/{file_id}"
    headers = {'x-apikey': api_key}
    response = requests.get(url, headers=headers)
    
    # Check if the request was successful (status code 200)
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": {"code": response.status_code, "message": response.text}}

# Streamlit UI
st.title("Image Virus Checker with VirusTotal")

# Get the user's VirusTotal API key
api_key = "1bcf6b4fc6fb75652ef58c6ddb7bccf4dd6141f2062bf040e973fb82bcce1acc"

# File upload
file = st.file_uploader("Upload an image file", type=["png", "jpg", "jpeg"])

# Input for File ID/Hash for VirusTotal v3 check
file_id = st.text_input("Enter File ID/Hash for VirusTotal v3 check")

if file is not None:
    st.image(file, caption="Uploaded Image", use_column_width=True)

    # Check the file with VirusTotal v2
    if st.button("Check for Viruses (v2)"):
        if api_key and file_id:
            st.write("Checking for viruses using VirusTotal API v2...")
            result_v2 = check_file_virustotal_v2(api_key, file)
            st.json(result_v2)
        else:
            st.write("Please enter your VirusTotal API key")

    # Check the file with VirusTotal v3 using requests
    if st.button("Check for Viruses (v3)"):
        if api_key and file_id:  # Checking both API key and file ID/hash are present
            st.write("Checking for viruses using VirusTotal API v3...")
            result_v3 = check_file_virustotal_v3(api_key, file_id)
            st.json(result_v3)
        else:
            st.write("Please enter your VirusTotal API key and File ID/Hash")
