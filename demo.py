"""demo.py
Simple end-to-end demonstration of the detection logic without using the web UI.
Generates a forged image, runs the detector, and prints the JSON result.

Usage:
    python demo.py
"""

from create_test_image import create_forged_image
from detector import CopyMoveDetector
import json


def main():
    print("[demo] creating test image...")
    create_forged_image()
    img_path = "static/uploads/test_forged.jpg"
    print(f"[demo] running detector on: {img_path}")
    det = CopyMoveDetector(method="SIFT")
    result = det.detect(img_path)
    print("[demo] analysis result:\n", json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
