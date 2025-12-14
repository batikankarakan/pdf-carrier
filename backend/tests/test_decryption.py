"""
Unit tests for decryption module
"""

import pytest
import json
import base64
import os
import sys
from io import BytesIO

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.decryption import (
    decrypt_pdf,
    decrypt_pdf_page_selection,
    parse_encrypted_file_metadata
)
from crypto.encryption import (
    encrypt_pdf,
    encrypt_pdf_page_selection
)


@pytest.fixture
def sample_pdf_bytes():
    """Create a sample PDF for testing"""
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter

    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)

    for i in range(3):
        c.drawString(100, 750, f"Test PDF Document - Page {i+1}")
        c.drawString(100, 700, f"Content for page {i+1}")
        c.showPage()

    c.save()
    buffer.seek(0)
    return buffer.read()


class TestDecryptPDF:
    """Tests for full PDF decryption"""

    def test_decrypt_basic(self, sample_pdf_bytes):
        """Test basic decryption"""
        encrypted_pdf, key_file = encrypt_pdf(sample_pdf_bytes, "test.pdf")

        decrypted_pdf, metadata = decrypt_pdf(encrypted_pdf, key_file)

        assert decrypted_pdf == sample_pdf_bytes
        assert metadata['verified'] == True

    def test_decrypt_returns_metadata(self, sample_pdf_bytes):
        """Test that decryption returns proper metadata"""
        encrypted_pdf, key_file = encrypt_pdf(sample_pdf_bytes, "test.pdf")

        decrypted_pdf, metadata = decrypt_pdf(encrypted_pdf, key_file)

        assert 'original_filename' in metadata
        assert 'algorithms_used' in metadata
        assert 'timestamp' in metadata
        assert 'version' in metadata
        assert 'integrity_check' in metadata
        assert metadata['integrity_check'] == 'PASSED'

    def test_decrypt_invalid_key_file_json(self, sample_pdf_bytes):
        """Test decryption with invalid JSON key file"""
        encrypted_pdf, _ = encrypt_pdf(sample_pdf_bytes, "test.pdf")

        with pytest.raises(ValueError, match="Invalid key file"):
            decrypt_pdf(encrypted_pdf, b"not valid json")

    def test_decrypt_missing_private_key(self, sample_pdf_bytes):
        """Test decryption with missing private key"""
        encrypted_pdf, key_file = encrypt_pdf(sample_pdf_bytes, "test.pdf")

        # Remove private key from key file
        key_data = json.loads(key_file.decode('utf-8'))
        del key_data['private_key']
        bad_key_file = json.dumps(key_data).encode('utf-8')

        with pytest.raises((ValueError, KeyError)):
            decrypt_pdf(encrypted_pdf, bad_key_file)

    def test_decrypt_tampered_hmac(self, sample_pdf_bytes):
        """Test that tampered HMAC is detected"""
        encrypted_pdf, key_file = encrypt_pdf(sample_pdf_bytes, "test.pdf")

        # Tamper with HMAC
        key_data = json.loads(key_file.decode('utf-8'))
        key_data['metadata']['hmac'] = base64.b64encode(b'fake_hmac').decode('utf-8')
        tampered_key_file = json.dumps(key_data).encode('utf-8')

        with pytest.raises(ValueError, match="HMAC verification failed"):
            decrypt_pdf(encrypted_pdf, tampered_key_file)

    def test_decrypt_wrong_key_file(self, sample_pdf_bytes):
        """Test decryption with wrong key file"""
        encrypted_pdf1, key_file1 = encrypt_pdf(sample_pdf_bytes, "test1.pdf")
        encrypted_pdf2, key_file2 = encrypt_pdf(sample_pdf_bytes, "test2.pdf")

        # Try to decrypt with wrong key file
        with pytest.raises(Exception):
            decrypt_pdf(encrypted_pdf1, key_file2)

    def test_decrypt_missing_metadata_field(self, sample_pdf_bytes):
        """Test decryption with missing metadata field"""
        encrypted_pdf, key_file = encrypt_pdf(sample_pdf_bytes, "test.pdf")

        # Remove required field
        key_data = json.loads(key_file.decode('utf-8'))
        del key_data['metadata']['algorithms']
        bad_key_file = json.dumps(key_data).encode('utf-8')

        with pytest.raises(ValueError, match="Missing required metadata"):
            decrypt_pdf(encrypted_pdf, bad_key_file)

    def test_decrypt_all_algorithm_combinations(self, sample_pdf_bytes):
        """Test decryption with various algorithm combinations"""
        algorithm_pairs = [
            ['AES-256-GCM', 'ChaCha20-Poly1305'],
            ['AES-256-GCM', 'AES-128-GCM'],
            ['AES-256-CBC', 'ChaCha20-Poly1305'],
            ['AES-256-GCM', 'DES'],
            ['DES', 'AES-128-GCM'],
        ]

        for algorithms in algorithm_pairs:
            encrypted_pdf, key_file = encrypt_pdf(
                sample_pdf_bytes, "test.pdf", algorithms=algorithms
            )
            decrypted_pdf, metadata = decrypt_pdf(encrypted_pdf, key_file)

            assert decrypted_pdf == sample_pdf_bytes
            assert metadata['algorithms_used'] == algorithms


class TestDecryptPDFPageSelection:
    """Tests for page selection decryption"""

    def test_decrypt_page_selection_basic(self, sample_pdf_bytes):
        """Test basic page selection decryption"""
        encrypted_pdf, key_file = encrypt_pdf_page_selection(
            sample_pdf_bytes, [1], "test.pdf"
        )

        decrypted_pdf, metadata = decrypt_pdf_page_selection(encrypted_pdf, key_file)

        assert decrypted_pdf == sample_pdf_bytes
        assert metadata['verified'] == True

    def test_decrypt_page_selection_multiple_pages(self, sample_pdf_bytes):
        """Test decryption of multiple encrypted pages"""
        encrypted_pdf, key_file = encrypt_pdf_page_selection(
            sample_pdf_bytes, [1, 2], "test.pdf"
        )

        decrypted_pdf, metadata = decrypt_pdf_page_selection(encrypted_pdf, key_file)

        assert decrypted_pdf == sample_pdf_bytes
        assert metadata['pages_encrypted'] == [1, 2]

    def test_decrypt_page_selection_returns_metadata(self, sample_pdf_bytes):
        """Test that page selection decryption returns proper metadata"""
        encrypted_pdf, key_file = encrypt_pdf_page_selection(
            sample_pdf_bytes, [1], "test.pdf"
        )

        decrypted_pdf, metadata = decrypt_pdf_page_selection(encrypted_pdf, key_file)

        assert 'original_filename' in metadata
        assert 'algorithms_used' in metadata
        assert 'pages_encrypted' in metadata
        assert 'total_pages' in metadata
        assert 'encryption_type' in metadata
        assert metadata['encryption_type'] == 'page_selection'

    def test_decrypt_page_selection_wrong_type(self, sample_pdf_bytes):
        """Test error when using wrong encryption type"""
        # Encrypt with full PDF encryption
        encrypted_pdf, key_file = encrypt_pdf(sample_pdf_bytes, "test.pdf")

        # Try to decrypt as page selection
        with pytest.raises(ValueError, match="page_selection"):
            decrypt_pdf_page_selection(encrypted_pdf, key_file)

    def test_decrypt_page_selection_invalid_json(self, sample_pdf_bytes):
        """Test page selection decryption with invalid key file"""
        encrypted_pdf, _ = encrypt_pdf_page_selection(
            sample_pdf_bytes, [1], "test.pdf"
        )

        with pytest.raises(ValueError, match="Invalid key file"):
            decrypt_pdf_page_selection(encrypted_pdf, b"not valid json")


class TestDecryptionVersionCompatibility:
    """Tests for version handling in decryption"""

    def test_version_4_1_decryption(self, sample_pdf_bytes):
        """Test decryption of version 4.1 files"""
        encrypted_pdf, key_file = encrypt_pdf(sample_pdf_bytes, "test.pdf")

        key_data = json.loads(key_file.decode('utf-8'))
        version = key_data['metadata']['version']

        # Should be version 4.x
        assert version.startswith('4.')

        # Should decrypt successfully
        decrypted_pdf, metadata = decrypt_pdf(encrypted_pdf, key_file)
        assert decrypted_pdf == sample_pdf_bytes

    def test_version_7_1_decryption(self, sample_pdf_bytes):
        """Test decryption of version 7.1 files"""
        encrypted_pdf, key_file = encrypt_pdf_page_selection(
            sample_pdf_bytes, [1], "test.pdf"
        )

        key_data = json.loads(key_file.decode('utf-8'))
        version = key_data['metadata']['version']

        # Should be version 7.x
        assert version.startswith('7.')

        # Should decrypt successfully
        decrypted_pdf, metadata = decrypt_pdf_page_selection(encrypted_pdf, key_file)
        assert decrypted_pdf == sample_pdf_bytes


class TestDecryptionEdgeCases:
    """Tests for edge cases in decryption"""

    def test_decrypt_large_pdf(self):
        """Test decryption of larger PDF"""
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import letter

        buffer = BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)

        # Create 20 pages
        for i in range(20):
            c.drawString(100, 750, f"Page {i+1} of 20")
            for j in range(10):
                c.drawString(100, 700 - j*30, f"Line {j+1}: Content...")
            c.showPage()

        c.save()
        buffer.seek(0)
        large_pdf = buffer.read()

        encrypted_pdf, key_file = encrypt_pdf(large_pdf, "large.pdf")
        decrypted_pdf, metadata = decrypt_pdf(encrypted_pdf, key_file)

        assert decrypted_pdf == large_pdf

    def test_decrypt_single_page_pdf(self):
        """Test decryption of single-page PDF"""
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import letter

        buffer = BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        c.drawString(100, 750, "Single page PDF")
        c.showPage()
        c.save()
        buffer.seek(0)
        single_pdf = buffer.read()

        encrypted_pdf, key_file = encrypt_pdf(single_pdf, "single.pdf")
        decrypted_pdf, metadata = decrypt_pdf(encrypted_pdf, key_file)

        assert decrypted_pdf == single_pdf

    def test_decrypt_preserves_binary_content(self, sample_pdf_bytes):
        """Test that binary PDF content is preserved exactly"""
        encrypted_pdf, key_file = encrypt_pdf(sample_pdf_bytes, "test.pdf")
        decrypted_pdf, metadata = decrypt_pdf(encrypted_pdf, key_file)

        # Exact byte-for-byte comparison
        assert decrypted_pdf == sample_pdf_bytes
        assert len(decrypted_pdf) == len(sample_pdf_bytes)


class TestHMACVerification:
    """Tests for HMAC integrity verification during decryption"""

    def test_hmac_passes_valid_file(self, sample_pdf_bytes):
        """Test that valid HMAC passes verification"""
        encrypted_pdf, key_file = encrypt_pdf(sample_pdf_bytes, "test.pdf")

        decrypted_pdf, metadata = decrypt_pdf(encrypted_pdf, key_file)

        assert metadata['integrity_check'] == 'PASSED'

    def test_hmac_detects_tampered_encrypted_data(self, sample_pdf_bytes):
        """Test that tampering with encrypted data is detected"""
        encrypted_pdf, key_file = encrypt_pdf(sample_pdf_bytes, "test.pdf")

        # Tamper with the encrypted PDF data in key file
        key_data = json.loads(key_file.decode('utf-8'))
        original_data = base64.b64decode(key_data['metadata']['encrypted_pdf_data'])

        # Flip some bits
        tampered_data = bytearray(original_data)
        if len(tampered_data) > 10:
            tampered_data[10] ^= 0xFF
        tampered_data = bytes(tampered_data)

        key_data['metadata']['encrypted_pdf_data'] = base64.b64encode(tampered_data).decode('utf-8')
        tampered_key_file = json.dumps(key_data).encode('utf-8')

        # Should fail HMAC verification
        with pytest.raises(ValueError, match="HMAC verification failed"):
            decrypt_pdf(encrypted_pdf, tampered_key_file)

    def test_hmac_detects_missing_hmac_key(self, sample_pdf_bytes):
        """Test that missing HMAC key is detected"""
        encrypted_pdf, key_file = encrypt_pdf(sample_pdf_bytes, "test.pdf")

        # Remove HMAC key
        key_data = json.loads(key_file.decode('utf-8'))
        del key_data['metadata']['hmac_key']
        bad_key_file = json.dumps(key_data).encode('utf-8')

        with pytest.raises(ValueError, match="Missing HMAC data"):
            decrypt_pdf(encrypted_pdf, bad_key_file)
