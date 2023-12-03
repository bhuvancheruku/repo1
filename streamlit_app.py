import streamlit as st
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
    url = f"https://www.virustotal.com/api/v3/files/{file_id}"
    headers = {'x-apikey': api_key}
    response = requests.get(url, headers=headers)
    return response.json()

# Streamlit UI
st.title("Image Virus Checker with VirusTotal")

# Get the user's VirusTotal API key
api_key = st.text_input("Enter your VirusTotal API key")

# File upload
file = st.file_uploader("Upload an image file", type=["png", "jpg", "jpeg"])

if file is not None:
    st.image(file, caption="Uploaded Image", use_column_width=True)

    # Check the file with VirusTotal v2
    if st.button("Check for Viruses (v2)"):
        if api_key:
            st.write("Checking for viruses using VirusTotal API v2...")
            result_v2 = check_file_virustotal_v2(api_key, file)
            st.json(result_v2)
        else:
            st.write("Please enter your VirusTotal API key")

    # Get the file ID or hash (You need to implement this logic)
    # file_id = get_file_id(file)  # You need a function to extract the file ID/hash

    # Check the file with VirusTotal v3
    if st.button("Check for Viruses (v3)"):
        if api_key and file_id:
            st.write("Checking for viruses using VirusTotal API v3...")
            result_v3 = check_file_virustotal_v3(api_key, file_id)
            st.json(result_v3)
        else:
            st.write("Please enter your VirusTotal API key and select an uploaded file")
