"""
create_test_image.py
Run this script to generate a sample forged image for testing.
Usage: python utils/create_test_image.py
"""

import cv2
import numpy as np
import os

def create_forged_image():
    # Create a sample natural-looking image
    img = np.zeros((400, 600, 3), dtype=np.uint8)

    # Background gradient
    for i in range(400):
        img[i] = [int(30 + i * 0.1), int(60 + i * 0.05), int(100 + i * 0.05)]

    # Draw some shapes to give the detector features to work with
    cv2.rectangle(img, (50, 50), (150, 150), (200, 100, 50), -1)
    cv2.circle(img, (300, 100), 60, (50, 180, 220), -1)
    cv2.rectangle(img, (400, 80), (550, 180), (180, 220, 80), -1)

    # Add some texture/noise
    noise = np.random.randint(0, 40, img.shape, dtype=np.uint8)
    img = cv2.add(img, noise)

    # Add text
    cv2.putText(img, "Sample Image", (180, 280),
                cv2.FONT_HERSHEY_SIMPLEX, 1.2, (255,255,255), 2)

    # --- COPY-MOVE FORGERY: copy rectangle region, paste elsewhere ---
    region = img[50:150, 50:150].copy()
    img[220:320, 350:450] = region  # paste at different location

    # Save
    # ensure we write inside the project folder (current file may be moved)
    project_root = os.path.dirname(os.path.abspath(__file__))
    out_dir = os.path.join(project_root, "static", "uploads")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "test_forged.jpg")
    cv2.imwrite(out_path, img)
    # avoid unicode print that can crash on Windows consoles
    print("[+] Test forged image saved to:", out_path)
    print("    Upload this image in the web app to test detection!")

if __name__ == "__main__":
    create_forged_image()
