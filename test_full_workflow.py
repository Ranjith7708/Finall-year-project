import requests
import os
import uuid

BASE_URL = "http://127.0.0.1:5000"
IMAGE_PATH = r"c:\Users\ranji\Downloads\files (1)\static\uploads\test_forged.jpg"

def verify_full_workflow():
    print("[...] Starting Full Workflow Verification...")
    session = requests.Session()
    unique_user = f"user_{uuid.uuid4().hex[:6]}"
    password = "password123"

    # 1. Registration
    print(f"[...] Registering new user: {unique_user}...")
    reg_data = {
        "username": unique_user,
        "password": password,
        "confirm_password": password
    }
    resp = session.post(f"{BASE_URL}/register", data=reg_data)
    if resp.status_code == 200 and "Login" in resp.text:
        print("[+] Registration successful.")
    else:
        print(f"[!] Registration failed. Status: {resp.status_code}")
        return

    # 2. Login
    print(f"[...] Logging in as {unique_user}...")
    login_data = {"username": unique_user, "password": password}
    resp = session.post(f"{BASE_URL}/login", data=login_data)
    if resp.status_code == 200 and "Analyze" in resp.text:
        print("[+] Login successful.")
    else:
        print(f"[!] Login failed. Status: {resp.status_code}")
        return

    # 3. Perform Analysis
    print("[...] Running analysis on image...")
    with open(IMAGE_PATH, "rb") as f:
        files = {"image": f}
        data = {"method": "SIFT"}
        resp = session.post(f"{BASE_URL}/analyze", files=files, data=data)
    
    if resp.status_code == 200:
        data = resp.json()
        analysis_id = data.get("analysis_id")
        print(f"[+] Analysis successful. ID: {analysis_id}")
    else:
        print(f"[!] Analysis failed. Status: {resp.status_code}")
        return

    # 4. Edit Report
    print(f"[...] Editing report {analysis_id}...")
    edit_data = {
        "analysis_id": analysis_id,
        "notes": "Verified suspicious texture in the left quadrant.",
        "conclusion": "Confirmed localized splicing."
    }
    resp = session.post(f"{BASE_URL}/report/save", data=edit_data)
    if resp.status_code == 200:
        print("[+] Report saved successfully.")
    else:
        print(f"[!] Report save failed. Status: {resp.status_code}")
        return

    # 5. Verify Download
    print("[...] Downloading final report...")
    resp = session.get(f"{BASE_URL}/report/{analysis_id}")
    if resp.status_code == 200:
        report_text = resp.text
        if "Confirmed localized splicing." in report_text and "Verified suspicious texture" in report_text:
            print("[+] Verified: Report contains custom expert conclusions.")
            print("[SUCCESS] Full workflow verified successfully!")
        else:
            print("[!] Report download verification failed: Custom content missing.")
    else:
        print(f"[!] Report download failed. Status: {resp.status_code}")

if __name__ == "__main__":
    verify_full_workflow()
