# 🔬 Deep Forensics — Copy-Move Image Forgery Detection

A Flask web application that detects **copy-move forgery** in images using **OpenCV (SIFT/ORB)** feature extraction and **Scikit-learn DBSCAN** clustering.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **Single Image Analysis** | Upload an image, detect copy-move forgery with confidence scoring |
| **Batch Processing** | Analyze multiple images at once with per-image results |
| **Analysis History** | View past analyses with timestamps and download reports |
| **EXIF Metadata Analysis** | Detect editing software, date mismatches, GPS data |
| **Dark / Light Mode** | Toggle between themes with localStorage persistence |
| **Detailed Reports** | Severity ratings, animated confidence gauge, downloadable reports |

---

## 📁 Project Structure

```
deep_forensics/
├── app.py                  # Flask main application (history, batch, metadata, reports)
├── detector.py             # Core SIFT/ORB detection algorithm
├── requirements.txt        # Python dependencies
├── templates/
│   └── index.html          # Web UI (tabs, dark mode, batch, history)
├── static/
│   ├── uploads/            # Uploaded images (auto-created)
│   └── results/            # Annotated result images (auto-created)
├── create_test_image.py    # Generate a test forged image
├── demo.py                 # CLI demo script
├── run_dev.bat             # Windows batch launcher
└── run_dev.ps1             # PowerShell dev script
```

---

## ⚙️ Setup Instructions

### Step 1 — Prerequisites
Make sure you have **Python 3.8+** installed.

### Step 2 — Create Virtual Environment
```bash
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # macOS / Linux
```

### Step 3 — Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4 — Run the App
```bash
python app.py
```

Open your browser at: **http://127.0.0.1:5000**

---

## 🚀 How It Works

| Step | Process |
|------|---------|
| 1 | Upload a suspicious image via the web UI |
| 2 | SIFT/ORB keypoints are extracted from the image |
| 3 | Feature descriptors are matched across all image regions |
| 4 | Suspicious pairs (spatially separated but visually identical) are filtered |
| 5 | DBSCAN clusters the suspicious regions |
| 6 | Annotated result highlights forged regions with confidence & severity |

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Web UI |
| POST | `/analyze` | Analyze single image |
| POST | `/analyze-batch` | Analyze multiple images |
| POST | `/metadata` | Extract EXIF metadata |
| GET | `/history` | Get analysis history |
| DELETE | `/history` | Clear history |
| GET | `/report/<id>` | Download analysis report |
| GET | `/health` | Server health check |

---

## 🧪 Test with a Forged Image

```bash
python create_test_image.py
python demo.py
```

Or invoke the detector from CLI:
```bash
python detector.py path/to/image.jpg -m SIFT
```

---

## 📸 Supported Formats
JPG, JPEG, PNG, BMP, TIFF, WEBP (Max 16MB)

---

## 👨‍💻 Technologies Used
- **Python 3.x** — Backend language
- **Flask** — Web framework
- **OpenCV** — Image processing + SIFT/ORB feature detection
- **Scikit-learn** — DBSCAN clustering
- **Pillow** — EXIF metadata extraction
- **NumPy** — Array operations
- **HTML/CSS/JS** — Frontend UI with dark/light mode
