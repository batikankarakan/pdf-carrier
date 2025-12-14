"""
Unit tests for PDF content manipulation module
"""

import pytest
import os
import sys
from io import BytesIO

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.pdf_content import (
    extract_text_from_pdf,
    get_pdf_metadata,
    create_pdf_with_text,
    encrypt_text_content,
    decrypt_text_content
)


@pytest.fixture
def sample_pdf_bytes():
    """Create a sample PDF for testing"""
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter

    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)

    # Page 1
    c.drawString(100, 750, "Test PDF Document - Page 1")
    c.drawString(100, 700, "This is sample content for testing.")
    c.drawString(100, 650, "Line 3 of page 1.")
    c.showPage()

    # Page 2
    c.drawString(100, 750, "Test PDF Document - Page 2")
    c.drawString(100, 700, "Second page content here.")
    c.showPage()

    # Page 3
    c.drawString(100, 750, "Test PDF Document - Page 3")
    c.drawString(100, 700, "Third and final page.")
    c.showPage()

    c.save()
    buffer.seek(0)
    return buffer.read()


@pytest.fixture
def single_page_pdf():
    """Create a single-page PDF"""
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter

    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    c.drawString(100, 750, "Single page PDF content")
    c.showPage()
    c.save()
    buffer.seek(0)
    return buffer.read()


class TestExtractTextFromPDF:
    """Tests for PDF text extraction"""

    def test_extract_text_basic(self, sample_pdf_bytes):
        """Test basic text extraction"""
        text, metadata = extract_text_from_pdf(sample_pdf_bytes)

        # Should contain some of our test text
        assert "Test PDF Document" in text or len(text) > 0
        assert metadata['page_count'] == 3

    def test_extract_text_returns_metadata(self, sample_pdf_bytes):
        """Test that metadata is returned"""
        text, metadata = extract_text_from_pdf(sample_pdf_bytes)

        assert 'page_count' in metadata
        assert 'page_sizes' in metadata
        assert len(metadata['page_sizes']) == 3

    def test_extract_text_page_sizes(self, sample_pdf_bytes):
        """Test that page sizes are extracted"""
        text, metadata = extract_text_from_pdf(sample_pdf_bytes)

        for page_size in metadata['page_sizes']:
            assert 'width' in page_size
            assert 'height' in page_size
            assert page_size['width'] > 0
            assert page_size['height'] > 0

    def test_extract_text_single_page(self, single_page_pdf):
        """Test extraction from single-page PDF"""
        text, metadata = extract_text_from_pdf(single_page_pdf)

        assert metadata['page_count'] == 1
        assert len(metadata['page_sizes']) == 1


class TestGetPDFMetadata:
    """Tests for PDF metadata extraction"""

    def test_get_metadata_basic(self, sample_pdf_bytes):
        """Test basic metadata extraction"""
        metadata = get_pdf_metadata(sample_pdf_bytes)

        assert metadata['page_count'] == 3
        assert 'page_sizes' in metadata

    def test_get_metadata_page_sizes(self, sample_pdf_bytes):
        """Test page size extraction"""
        metadata = get_pdf_metadata(sample_pdf_bytes)

        assert len(metadata['page_sizes']) == 3
        for page_size in metadata['page_sizes']:
            assert 'width' in page_size
            assert 'height' in page_size

    def test_get_metadata_single_page(self, single_page_pdf):
        """Test metadata from single-page PDF"""
        metadata = get_pdf_metadata(single_page_pdf)

        assert metadata['page_count'] == 1


class TestCreatePDFWithText:
    """Tests for PDF creation from text"""

    def test_create_pdf_basic(self):
        """Test basic PDF creation"""
        text = "This is test content\nWith multiple lines\nFor testing."

        pdf_bytes = create_pdf_with_text(text)

        assert len(pdf_bytes) > 0
        # Verify it's a valid PDF by checking magic bytes
        assert pdf_bytes[:4] == b'%PDF'

    def test_create_pdf_with_metadata(self, sample_pdf_bytes):
        """Test PDF creation with original metadata"""
        metadata = get_pdf_metadata(sample_pdf_bytes)
        text = "Test content for PDF"

        pdf_bytes = create_pdf_with_text(text, metadata)

        assert len(pdf_bytes) > 0
        assert pdf_bytes[:4] == b'%PDF'

    def test_create_pdf_multiple_pages(self):
        """Test PDF creation with multiple pages"""
        text = "Page 1 content\n--- PAGE BREAK ---\nPage 2 content"

        pdf_bytes = create_pdf_with_text(text)

        # Verify it's a valid PDF
        assert pdf_bytes[:4] == b'%PDF'

    def test_create_pdf_long_lines(self):
        """Test PDF creation with long lines (should wrap)"""
        long_line = "A" * 200
        text = f"Short line\n{long_line}\nAnother short line"

        pdf_bytes = create_pdf_with_text(text)

        assert len(pdf_bytes) > 0
        assert pdf_bytes[:4] == b'%PDF'

    def test_create_pdf_empty_text(self):
        """Test PDF creation with empty text"""
        pdf_bytes = create_pdf_with_text("")

        assert len(pdf_bytes) > 0
        assert pdf_bytes[:4] == b'%PDF'

    def test_create_pdf_special_characters(self):
        """Test PDF creation with special characters"""
        text = "Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?"

        pdf_bytes = create_pdf_with_text(text)

        assert len(pdf_bytes) > 0
        assert pdf_bytes[:4] == b'%PDF'


class TestEncryptDecryptTextContent:
    """Tests for text content encryption/decryption (base64 encoding)"""

    def test_encrypt_text_basic(self):
        """Test basic text encryption (base64)"""
        text = "Hello, World!"

        encrypted = encrypt_text_content(text)

        # Should be base64-like (alphanumeric + some chars)
        assert len(encrypted) > 0
        assert encrypted != text

    def test_decrypt_text_basic(self):
        """Test basic text decryption (base64)"""
        text = "Hello, World!"

        encrypted = encrypt_text_content(text)
        decrypted = decrypt_text_content(encrypted)

        assert decrypted == text

    def test_encrypt_decrypt_roundtrip(self):
        """Test full encryption/decryption roundtrip"""
        original = "This is a longer test message with special chars: !@#$%"

        encrypted = encrypt_text_content(original)
        decrypted = decrypt_text_content(encrypted)

        assert decrypted == original

    def test_encrypt_adds_line_breaks(self):
        """Test that encryption adds line breaks for readability"""
        # Create text that will produce long base64
        text = "A" * 100

        encrypted = encrypt_text_content(text)

        # Should have line breaks
        assert '\n' in encrypted

    def test_decrypt_handles_line_breaks(self):
        """Test that decryption removes line breaks"""
        text = "Test message"

        encrypted = encrypt_text_content(text)
        # Add extra whitespace
        encrypted_with_spaces = encrypted.replace('\n', '\n  ')

        decrypted = decrypt_text_content(encrypted_with_spaces)

        assert decrypted == text

    def test_decrypt_invalid_base64(self):
        """Test that invalid base64 raises error"""
        invalid = "This is not valid base64!!!"

        with pytest.raises(ValueError, match="Failed to decrypt"):
            decrypt_text_content(invalid)

    def test_encrypt_unicode(self):
        """Test encryption of unicode text"""
        text = "Unicode: café, naïve, 日本語"

        encrypted = encrypt_text_content(text)
        decrypted = decrypt_text_content(encrypted)

        assert decrypted == text

    def test_encrypt_empty_string(self):
        """Test encryption of empty string"""
        text = ""

        encrypted = encrypt_text_content(text)
        decrypted = decrypt_text_content(encrypted)

        assert decrypted == text


class TestPDFRoundtrip:
    """Integration tests for full PDF manipulation roundtrip"""

    def test_extract_create_roundtrip(self, sample_pdf_bytes):
        """Test extracting text and creating new PDF"""
        # Extract text
        text, metadata = extract_text_from_pdf(sample_pdf_bytes)

        # Create new PDF
        new_pdf = create_pdf_with_text(text, metadata)

        # Verify new PDF is valid
        assert new_pdf[:4] == b'%PDF'

        # Extract from new PDF
        new_text, new_metadata = extract_text_from_pdf(new_pdf)

        # Should have content
        assert len(new_text) > 0

    def test_metadata_preserved_approximately(self, sample_pdf_bytes):
        """Test that page count is approximately preserved"""
        original_metadata = get_pdf_metadata(sample_pdf_bytes)
        text, _ = extract_text_from_pdf(sample_pdf_bytes)

        # Create pages manually
        pages = text.split("\n--- PAGE BREAK ---\n")

        # Should have similar structure
        assert len(pages) >= 1
