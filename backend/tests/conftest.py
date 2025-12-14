"""
Pytest configuration and fixtures for PDF Carrier tests
"""

import pytest
import os
import sys
from io import BytesIO

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter


@pytest.fixture
def sample_pdf_bytes():
    """Generate a simple PDF for testing"""
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)

    # Page 1
    c.drawString(100, 750, "Test PDF Document - Page 1")
    c.drawString(100, 700, "This is a sample PDF for testing encryption.")
    c.drawString(100, 650, "It contains multiple pages with text content.")
    c.showPage()

    # Page 2
    c.drawString(100, 750, "Test PDF Document - Page 2")
    c.drawString(100, 700, "Second page content for testing.")
    c.drawString(100, 650, "More text to encrypt and decrypt.")
    c.showPage()

    # Page 3
    c.drawString(100, 750, "Test PDF Document - Page 3")
    c.drawString(100, 700, "Third page with additional content.")
    c.drawString(100, 650, "Final page of the test document.")
    c.showPage()

    c.save()
    buffer.seek(0)
    return buffer.read()


@pytest.fixture
def sample_plaintext():
    """Sample plaintext for encryption tests"""
    return b"This is a test message for encryption. It should be encrypted and decrypted correctly!"


@pytest.fixture
def large_plaintext():
    """Large plaintext for stress testing"""
    return b"A" * 1024 * 1024  # 1MB of data


@pytest.fixture
def empty_plaintext():
    """Empty plaintext for edge case testing"""
    return b""


@pytest.fixture
def binary_data():
    """Binary data with all byte values"""
    return bytes(range(256)) * 100
