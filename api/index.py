"""
Vercel serverless entry point for Deep Forensics Flask app.
Vercel looks for `app` (WSGI callable) in this file.
"""
import sys
import os

# Add project root to path so imports from app.py work
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app  # Import the Flask app

# Vercel WSGI handler — Vercel will call this
app = app
