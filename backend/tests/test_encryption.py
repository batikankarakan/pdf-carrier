"""
Unit tests for encryption/decryption workflows
"""

import pytest
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.encryption import (
    encrypt_pdf,
    encrypt_pdf_page_selection
)
from crypto.decryption import (
    decrypt_pdf,
    decrypt_pdf_page_selection
)
from crypto.key_management import (
    generate_encryption_keys,
    create_key_file,
    load_key_file,
    encapsulate_symmetric_keys,
    decapsulate_symmetric_keys
)
from crypto.algorithms import RSACipher


class TestKeyManagement:
    """Tests for key management functions"""

    def test_generate_encryption_keys(self):
        """Test that all required keys are generated"""
        keys = generate_encryption_keys()

        assert 'aes_key' in keys
        assert 'chacha_key' in keys
        assert 'rsa_private' in keys
        assert 'rsa_public' in keys

        assert len(keys['aes_key']) == 32
        assert len(keys['chacha_key']) == 32

    def test_create_key_file(self):
        """Test key file creation"""
        private_key, public_key = RSACipher.generate_keypair(key_size=2048)
        algorithms = ['AES-256-GCM', 'ChaCha20-Poly1305']

        key_file_bytes = create_key_file(private_key, public_key, algorithms)

        # Parse and verify
        key_file_data = json.loads(key_file_bytes.decode('utf-8'))

        assert key_file_data['version'] == '1.0'
        assert key_file_data['key_type'] == 'RSA_PRIVATE'
        assert key_file_data['key_size'] == 4096
        assert 'private_key_pem' in key_file_data
        assert 'public_key_pem' in key_file_data
        assert key_file_data['algorithm_pool'] == algorithms

    def test_load_key_file(self):
        """Test key file loading"""
        private_key, public_key = RSACipher.generate_keypair(key_size=2048)
        algorithms = ['AES-256-GCM']

        key_file_bytes = create_key_file(private_key, public_key, algorithms)
        loaded = load_key_file(key_file_bytes)

        assert 'private_key' in loaded
        assert 'public_key' in loaded
        assert 'metadata' in loaded
        assert loaded['metadata']['algorithm_pool'] == algorithms

    def test_key_encapsulation_roundtrip(self):
        """Test symmetric key encapsulation and decapsulation"""
        private_key, public_key = RSACipher.generate_keypair(key_size=2048)

        aes_key = os.urandom(32)
        chacha_key = os.urandom(32)

        # Encapsulate
        encrypted_keys = encapsulate_symmetric_keys(aes_key, chacha_key, public_key)

        # Decapsulate
        recovered_aes, recovered_chacha = decapsulate_symmetric_keys(
            encrypted_keys, private_key
        )

        assert recovered_aes == aes_key
        assert recovered_chacha == chacha_key

    def test_invalid_key_file_format(self):
        """Test that invalid key file raises error"""
        invalid_data = b"not valid json"

        with pytest.raises(ValueError):
            load_key_file(invalid_data)

    def test_missing_key_file_fields(self):
        """Test that missing fields raise error"""
        incomplete_data = json.dumps({"version": "1.0"}).encode('utf-8')

        with pytest.raises(ValueError):
            load_key_file(incomplete_data)


class TestFullPDFEncryption:
    """Tests for full PDF encryption workflow"""

    def test_encrypt_pdf_basic(self, sample_pdf_bytes):
        """Test basic PDF encryption"""
        encrypted_pdf, key_file = encrypt_pdf(sample_pdf_bytes, "test.pdf")

        # Parse key file to check metadata
        import json
        key_data = json.loads(key_file.decode('utf-8'))

        assert len(encrypted_pdf) > 0
        assert len(key_file) > 0
        assert 'metadata' in key_data
        assert 'algorithms' in key_data['metadata']
        assert len(key_data['metadata']['algorithms']) == 2

    def test_encrypt_pdf_with_specific_algorithms(self, sample_pdf_bytes):
        """Test PDF encryption with specific algorithms"""
        algorithms = ['AES-256-GCM', 'ChaCha20-Poly1305']
        encrypted_pdf, key_file = encrypt_pdf(sample_pdf_bytes, "test.pdf", algorithms=algorithms)

        import json
        key_data = json.loads(key_file.decode('utf-8'))
        assert key_data['metadata']['algorithms'] == algorithms

    def test_encrypt_decrypt_roundtrip(self, sample_pdf_bytes):
        """Test full encryption/decryption roundtrip"""
        # Encrypt
        encrypted_pdf, key_file = encrypt_pdf(sample_pdf_bytes, "test.pdf")

        # Decrypt
        decrypted_pdf, metadata = decrypt_pdf(encrypted_pdf, key_file)

        assert decrypted_pdf == sample_pdf_bytes

    def test_encrypted_pdf_differs_from_original(self, sample_pdf_bytes):
        """Test that encrypted PDF differs from original"""
        encrypted_pdf, key_file = encrypt_pdf(sample_pdf_bytes, "test.pdf")
        assert encrypted_pdf != sample_pdf_bytes

    def test_wrong_key_file_fails(self, sample_pdf_bytes):
        """Test that wrong key file fails decryption"""
        # Encrypt with one key
        encrypted_pdf1, key_file1 = encrypt_pdf(sample_pdf_bytes, "test1.pdf")

        # Encrypt again to get different key
        encrypted_pdf2, key_file2 = encrypt_pdf(sample_pdf_bytes, "test2.pdf")

        # Try to decrypt with wrong key
        with pytest.raises(Exception):
            decrypt_pdf(encrypted_pdf1, key_file2)

    def test_all_algorithm_combinations(self, sample_pdf_bytes):
        """Test various algorithm combinations"""
        algorithm_pairs = [
            ['AES-256-GCM', 'ChaCha20-Poly1305'],
            ['AES-256-GCM', 'AES-128-GCM'],
            ['AES-256-CBC', 'ChaCha20-Poly1305'],
            ['AES-256-GCM', 'DES'],
            ['DES', 'AES-128-GCM'],
        ]

        for algorithms in algorithm_pairs:
            encrypted_pdf, key_file = encrypt_pdf(sample_pdf_bytes, "test.pdf", algorithms=algorithms)
            decrypted_pdf, metadata = decrypt_pdf(encrypted_pdf, key_file)
            assert decrypted_pdf == sample_pdf_bytes, \
                f"Failed for {algorithms}"


class TestPageSelectionEncryption:
    """Tests for page selection encryption"""

    def test_encrypt_single_page(self, sample_pdf_bytes):
        """Test encrypting a single page"""
        # Note: encrypt_pdf_page_selection(pdf_bytes, pages, original_filename, algorithms=None)
        encrypted_pdf, key_file = encrypt_pdf_page_selection(
            sample_pdf_bytes,
            [1],  # pages
            "test.pdf"  # original_filename
        )

        import json
        key_data = json.loads(key_file.decode('utf-8'))

        assert len(encrypted_pdf) > 0
        assert len(key_file) > 0
        assert key_data['metadata'].get('pages_encrypted') == [1]

    def test_encrypt_multiple_pages(self, sample_pdf_bytes):
        """Test encrypting multiple pages"""
        encrypted_pdf, key_file = encrypt_pdf_page_selection(
            sample_pdf_bytes,
            [1, 3],  # pages
            "test.pdf"
        )

        import json
        key_data = json.loads(key_file.decode('utf-8'))
        assert key_data['metadata'].get('pages_encrypted') == [1, 3]

    def test_encrypt_decrypt_page_selection_roundtrip(self, sample_pdf_bytes):
        """Test page selection encryption/decryption roundtrip"""
        # Encrypt pages 1 and 2
        encrypted_pdf, key_file = encrypt_pdf_page_selection(
            sample_pdf_bytes,
            [1, 2],  # pages
            "test.pdf"
        )

        # Decrypt
        decrypted_pdf, metadata = decrypt_pdf_page_selection(
            encrypted_pdf,
            key_file
        )

        # Original PDF should be restored
        assert decrypted_pdf == sample_pdf_bytes

    def test_page_selection_with_specific_algorithms(self, sample_pdf_bytes):
        """Test page selection with specific algorithms"""
        algorithms = ['AES-256-CBC', 'DES']
        encrypted_pdf, key_file = encrypt_pdf_page_selection(
            sample_pdf_bytes,
            [2],  # pages
            "test.pdf",
            algorithms=algorithms
        )

        import json
        key_data = json.loads(key_file.decode('utf-8'))
        assert key_data['metadata']['algorithms'] == algorithms


class TestHMACVerification:
    """Tests for HMAC integrity verification"""

    def test_hmac_verification_passes(self, sample_pdf_bytes):
        """Test that valid HMAC verification passes"""
        encrypted_pdf, key_file = encrypt_pdf(sample_pdf_bytes, "test.pdf")

        # Should not raise exception
        decrypted_pdf, metadata = decrypt_pdf(encrypted_pdf, key_file)

        assert decrypted_pdf == sample_pdf_bytes

    def test_tampered_encrypted_pdf_fails(self, sample_pdf_bytes):
        """Test that tampered encrypted PDF fails HMAC verification"""
        encrypted_pdf, key_file = encrypt_pdf(sample_pdf_bytes, "test.pdf")

        # Tamper with the key file metadata
        key_file_data = json.loads(key_file.decode('utf-8'))

        # Modify the HMAC tag if present
        if 'hmac' in key_file_data.get('metadata', {}):
            key_file_data['metadata']['hmac'] = 'aW52YWxpZF9obWFj'  # base64 of 'invalid_hmac'

        tampered_key_file = json.dumps(key_file_data).encode('utf-8')

        # This should fail
        with pytest.raises(Exception):
            decrypt_pdf(encrypted_pdf, tampered_key_file)


class TestEdgeCases:
    """Tests for edge cases"""

    def test_single_page_pdf(self):
        """Test encryption of single-page PDF"""
        from io import BytesIO
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import letter

        buffer = BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        c.drawString(100, 750, "Single page PDF")
        c.showPage()
        c.save()
        buffer.seek(0)
        single_page_pdf = buffer.read()

        encrypted_pdf, key_file = encrypt_pdf(single_page_pdf, "single.pdf")
        decrypted_pdf, metadata = decrypt_pdf(encrypted_pdf, key_file)

        assert decrypted_pdf == single_page_pdf

    def test_pdf_with_special_characters(self):
        """Test PDF with special characters in text"""
        from io import BytesIO
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import letter

        buffer = BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        c.drawString(100, 750, "Special: !@#$%^&*()_+-=[]{}|;':\",./<>?")
        c.showPage()
        c.save()
        buffer.seek(0)
        special_pdf = buffer.read()

        encrypted_pdf, key_file = encrypt_pdf(special_pdf, "special.pdf")
        decrypted_pdf, metadata = decrypt_pdf(encrypted_pdf, key_file)

        assert decrypted_pdf == special_pdf

    def test_large_pdf(self):
        """Test encryption of larger PDF"""
        from io import BytesIO
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import letter

        buffer = BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)

        # Create 20 pages
        for i in range(20):
            c.drawString(100, 750, f"Page {i+1} of 20")
            for j in range(10):
                c.drawString(100, 700 - j*30, f"Line {j+1}: Lorem ipsum dolor sit amet, consectetur adipiscing elit.")
            c.showPage()

        c.save()
        buffer.seek(0)
        large_pdf = buffer.read()

        encrypted_pdf, key_file = encrypt_pdf(large_pdf, "large.pdf")
        decrypted_pdf, metadata = decrypt_pdf(encrypted_pdf, key_file)

        assert decrypted_pdf == large_pdf


class TestVersionCompatibility:
    """Tests for version compatibility"""

    def test_version_4_0_format(self, sample_pdf_bytes):
        """Test that encryption produces version 4.x format"""
        encrypted_pdf, key_file = encrypt_pdf(sample_pdf_bytes, "test.pdf")

        key_file_data = json.loads(key_file.decode('utf-8'))
        metadata = key_file_data.get('metadata', {})

        # Check version is 4.x
        version = metadata.get('version', '')
        assert version.startswith('4.'), f"Expected version 4.x, got {version}"

    def test_page_selection_version_7_format(self, sample_pdf_bytes):
        """Test that page selection produces version 7.x format"""
        encrypted_pdf, key_file = encrypt_pdf_page_selection(
            sample_pdf_bytes,
            [1],  # pages
            "test.pdf"
        )

        key_file_data = json.loads(key_file.decode('utf-8'))
        metadata = key_file_data.get('metadata', {})

        # Check version is 7.x
        version = metadata.get('version', '')
        assert version.startswith('7.'), f"Expected version 7.x, got {version}"
