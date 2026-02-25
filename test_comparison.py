import requests
import os

BASE_URL = "http://127.0.0.1:5000"
IMAGE_PATH = r"c:\Users\ranji\Downloads\files (1)\static\uploads\test_forged.jpg"

def test_comparison():
    print("[...] Starting Multi-Algorithm Verification...")
    session = requests.Session()
    
    # 1. Login
    print("[...] Logging in...")
    login_data = {"username": "admin", "password": "password123"}
    resp = session.post(f"{BASE_URL}/login", data=login_data)
    if resp.status_code == 200 and "Analyze" in resp.text:
        print("[+] Login successful.")
    else:
        print(f"[!] Login failed. Status: {resp.status_code}")
        return

    # 2. Run Comparison
    print("[...] Running comparison (SIFT & ORB)...")
    with open(IMAGE_PATH, "rb") as f:
        files = {"image": f}
        data = {"methods": ["SIFT", "ORB"]}
        resp = session.post(f"{BASE_URL}/analyze-compare", files=files, data=data)
    
    if resp.status_code == 200:
        print("[+] Comparison successful.")
        results = resp.json()
        print(f"[+] Multi-Analysis ID: {results.get('analysis_id')}")
        
        for method, res in results.get("results", {}).items():
            print(f"-- Method: {method} --")
            print(f"   Detected: {res.get('detected')}")
            print(f"   Confidence: {res.get('confidence')}%")
            print(f"   Image: {res.get('result_image')}")
            
            # Verify result image exists
            res_path = os.path.join(r"c:\Users\ranji\Downloads\files (1)\static\results", res.get("result_image"))
            if os.path.exists(res_path):
                print(f"   [OK] Result image exists at: {res_path}")
            else:
                print(f"   [!] Result image MISSING at: {res_path}")
    else:
        print(f"[!] Comparison failed with status: {resp.status_code}")
        print(resp.text)

if __name__ == "__main__":
    test_comparison()
