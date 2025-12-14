"""
Unit tests for API endpoints
"""

import pytest
import os
import sys
from io import BytesIO
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import app

client = TestClient(app)


@pytest.fixture
def sample_pdf_file():
    """Create a sample PDF file for upload"""
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter

    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)

    c.drawString(100, 750, "Test PDF Document - Page 1")
    c.drawString(100, 700, "This is sample content for API testing.")
    c.showPage()

    c.drawString(100, 750, "Test PDF Document - Page 2")
    c.drawString(100, 700, "Second page content.")
    c.showPage()

    c.save()
    buffer.seek(0)
    return buffer


class TestHealthEndpoint:
    """Tests for health check endpoint"""

    def test_health_check(self):
        """Test health endpoint returns OK"""
        response = client.get("/api/health")

        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'healthy'


class TestAlgorithmsEndpoint:
    """Tests for algorithms listing endpoint"""

    def test_get_algorithms(self):
        """Test algorithms endpoint returns list"""
        response = client.get("/api/algorithms")

        assert response.status_code == 200
        data = response.json()
        # The API returns a dict with 'algorithms' key
        assert 'algorithms' in data
        assert isinstance(data['algorithms'], list)
        assert len(data['algorithms']) > 0

        # Check algorithm structure
        for algo in data['algorithms']:
            assert 'name' in algo
            # key_size or output_size depending on algorithm type
            assert 'key_size' in algo or 'output_size' in algo

    def test_algorithms_include_expected(self):
        """Test that expected algorithms are present"""
        response = client.get("/api/algorithms")
        data = response.json()

        algorithm_names = [algo['name'] for algo in data['algorithms']]

        expected = ['AES-256-GCM', 'AES-128-GCM', 'ChaCha20-Poly1305', 'AES-256-CBC', 'DES']
        for expected_algo in expected:
            assert expected_algo in algorithm_names, f"{expected_algo} not found"


class TestEncryptEndpoint:
    """Tests for encryption endpoint"""

    def test_encrypt_pdf(self, sample_pdf_file):
        """Test basic PDF encryption"""
        response = client.post(
            "/api/encrypt",
            files={"file": ("test.pdf", sample_pdf_file, "application/pdf")}
        )

        assert response.status_code == 200
        data = response.json()

        assert 'encrypted_file' in data
        assert 'key_file' in data
        assert 'algorithms' in data
        assert 'timestamp' in data
        assert 'original_filename' in data

        assert len(data['algorithms']) == 2
        assert data['original_filename'] == 'test.pdf'

    def test_encrypt_with_specific_algorithms(self, sample_pdf_file):
        """Test encryption with specific algorithms"""
        import json

        response = client.post(
            "/api/encrypt",
            files={"file": ("test.pdf", sample_pdf_file, "application/pdf")},
            data={"algorithms": json.dumps(['AES-256-GCM', 'ChaCha20-Poly1305'])}
        )

        assert response.status_code == 200
        data = response.json()
        assert data['algorithms'] == ['AES-256-GCM', 'ChaCha20-Poly1305']

    def test_encrypt_invalid_file_type(self):
        """Test encryption with invalid file type"""
        response = client.post(
            "/api/encrypt",
            files={"file": ("test.txt", BytesIO(b"not a pdf"), "text/plain")}
        )

        # Should fail or return error
        assert response.status_code in [400, 422, 500]

    def test_encrypt_empty_file(self):
        """Test encryption with empty file"""
        response = client.post(
            "/api/encrypt",
            files={"file": ("empty.pdf", BytesIO(b""), "application/pdf")}
        )

        # Should fail
        assert response.status_code in [400, 422, 500]


class TestDecryptEndpoint:
    """Tests for decryption endpoint"""

    def test_decrypt_pdf(self, sample_pdf_file):
        """Test basic PDF decryption"""
        # First encrypt
        encrypt_response = client.post(
            "/api/encrypt",
            files={"file": ("test.pdf", sample_pdf_file, "application/pdf")}
        )

        assert encrypt_response.status_code == 200
        encrypt_data = encrypt_response.json()

        # Prepare files for decryption
        import base64
        encrypted_pdf = base64.b64decode(encrypt_data['encrypted_file'])
        key_file = base64.b64decode(encrypt_data['key_file'])

        # Decrypt
        decrypt_response = client.post(
            "/api/decrypt",
            files={
                "encrypted_file": ("encrypted.pdf", BytesIO(encrypted_pdf), "application/pdf"),
                "key_file": ("key.json", BytesIO(key_file), "application/json")
            }
        )

        assert decrypt_response.status_code == 200
        decrypt_data = decrypt_response.json()

        assert 'decrypted_file' in decrypt_data
        # API returns 'metadata' with 'algorithms_used' inside
        assert 'metadata' in decrypt_data
        assert 'algorithms_used' in decrypt_data['metadata']

    def test_decrypt_with_wrong_key(self, sample_pdf_file):
        """Test decryption with wrong key file"""
        import base64

        # Encrypt file 1
        response1 = client.post(
            "/api/encrypt",
            files={"file": ("test1.pdf", sample_pdf_file, "application/pdf")}
        )
        data1 = response1.json()

        # Encrypt file 2 (to get different key)
        sample_pdf_file.seek(0)
        response2 = client.post(
            "/api/encrypt",
            files={"file": ("test2.pdf", sample_pdf_file, "application/pdf")}
        )
        data2 = response2.json()

        # Try to decrypt file1 with key2
        encrypted_pdf1 = base64.b64decode(data1['encrypted_file'])
        key_file2 = base64.b64decode(data2['key_file'])

        decrypt_response = client.post(
            "/api/decrypt",
            files={
                "encrypted_file": ("encrypted.pdf", BytesIO(encrypted_pdf1), "application/pdf"),
                "key_file": ("key.json", BytesIO(key_file2), "application/json")
            }
        )

        # Should fail
        assert decrypt_response.status_code == 400

    def test_decrypt_missing_files(self):
        """Test decryption with missing files"""
        response = client.post(
            "/api/decrypt",
            files={}
        )

        assert response.status_code == 422


class TestPageSelectionEndpoint:
    """Tests for page selection encryption endpoint"""

    def test_encrypt_page_selection(self, sample_pdf_file):
        """Test page selection encryption"""
        import json

        response = client.post(
            "/api/encrypt/page-selection",
            files={"file": ("test.pdf", sample_pdf_file, "application/pdf")},
            data={"pages": json.dumps([1])}
        )

        assert response.status_code == 200
        data = response.json()

        assert 'encrypted_file' in data
        assert 'key_file' in data
        assert 'algorithms' in data

    def test_encrypt_multiple_pages(self, sample_pdf_file):
        """Test encrypting multiple pages"""
        import json

        response = client.post(
            "/api/encrypt/page-selection",
            files={"file": ("test.pdf", sample_pdf_file, "application/pdf")},
            data={"pages": json.dumps([1, 2])}
        )

        assert response.status_code == 200

    def test_decrypt_page_selection(self, sample_pdf_file):
        """Test page selection decryption"""
        import json
        import base64

        # Encrypt
        encrypt_response = client.post(
            "/api/encrypt/page-selection",
            files={"file": ("test.pdf", sample_pdf_file, "application/pdf")},
            data={"pages": json.dumps([1])}
        )

        assert encrypt_response.status_code == 200
        encrypt_data = encrypt_response.json()

        # Decrypt
        encrypted_pdf = base64.b64decode(encrypt_data['encrypted_file'])
        key_file = base64.b64decode(encrypt_data['key_file'])

        decrypt_response = client.post(
            "/api/decrypt/page-selection",
            files={
                "encrypted_file": ("encrypted.pdf", BytesIO(encrypted_pdf), "application/pdf"),
                "key_file": ("key.json", BytesIO(key_file), "application/json")
            }
        )

        assert decrypt_response.status_code == 200


class TestEncryptDecryptRoundtrip:
    """Integration tests for full roundtrip"""

    def test_full_encryption_roundtrip(self, sample_pdf_file):
        """Test complete encryption and decryption cycle"""
        import base64

        original_content = sample_pdf_file.read()
        sample_pdf_file.seek(0)

        # Encrypt
        encrypt_response = client.post(
            "/api/encrypt",
            files={"file": ("test.pdf", sample_pdf_file, "application/pdf")}
        )

        assert encrypt_response.status_code == 200
        encrypt_data = encrypt_response.json()

        # Decrypt
        encrypted_pdf = base64.b64decode(encrypt_data['encrypted_file'])
        key_file = base64.b64decode(encrypt_data['key_file'])

        decrypt_response = client.post(
            "/api/decrypt",
            files={
                "encrypted_file": ("encrypted.pdf", BytesIO(encrypted_pdf), "application/pdf"),
                "key_file": ("key.json", BytesIO(key_file), "application/json")
            }
        )

        assert decrypt_response.status_code == 200
        decrypt_data = decrypt_response.json()

        decrypted_content = base64.b64decode(decrypt_data['decrypted_file'])
        assert decrypted_content == original_content

    def test_page_selection_roundtrip(self, sample_pdf_file):
        """Test complete page selection encryption/decryption cycle"""
        import json
        import base64

        original_content = sample_pdf_file.read()
        sample_pdf_file.seek(0)

        # Encrypt page 1
        encrypt_response = client.post(
            "/api/encrypt/page-selection",
            files={"file": ("test.pdf", sample_pdf_file, "application/pdf")},
            data={"pages": json.dumps([1])}
        )

        assert encrypt_response.status_code == 200
        encrypt_data = encrypt_response.json()

        # Decrypt
        encrypted_pdf = base64.b64decode(encrypt_data['encrypted_file'])
        key_file = base64.b64decode(encrypt_data['key_file'])

        decrypt_response = client.post(
            "/api/decrypt/page-selection",
            files={
                "encrypted_file": ("encrypted.pdf", BytesIO(encrypted_pdf), "application/pdf"),
                "key_file": ("key.json", BytesIO(key_file), "application/json")
            }
        )

        assert decrypt_response.status_code == 200
        decrypt_data = decrypt_response.json()

        decrypted_content = base64.b64decode(decrypt_data['decrypted_file'])
        assert decrypted_content == original_content


class TestErrorHandling:
    """Tests for API error handling"""

    def test_invalid_json_algorithms(self, sample_pdf_file):
        """Test handling of invalid JSON in algorithms parameter"""
        response = client.post(
            "/api/encrypt",
            files={"file": ("test.pdf", sample_pdf_file, "application/pdf")},
            data={"algorithms": "not valid json"}
        )

        # Should handle gracefully (400 for bad request, or continue without algorithms)
        assert response.status_code in [200, 400, 422, 500]

    def test_unknown_algorithm(self, sample_pdf_file):
        """Test handling of unknown algorithm"""
        import json

        response = client.post(
            "/api/encrypt",
            files={"file": ("test.pdf", sample_pdf_file, "application/pdf")},
            data={"algorithms": json.dumps(['UNKNOWN-ALGO', 'AES-256-GCM'])}
        )

        # Should fail or fall back
        assert response.status_code in [200, 400, 500]

    def test_corrupted_encrypted_file(self, sample_pdf_file):
        """Test handling of corrupted encrypted file"""
        import base64

        # First encrypt to get valid key file
        encrypt_response = client.post(
            "/api/encrypt",
            files={"file": ("test.pdf", sample_pdf_file, "application/pdf")}
        )
        encrypt_data = encrypt_response.json()
        key_file = base64.b64decode(encrypt_data['key_file'])

        # Try to decrypt corrupted data
        corrupted = b"this is not encrypted pdf data"

        decrypt_response = client.post(
            "/api/decrypt",
            files={
                "encrypted_file": ("corrupted.pdf", BytesIO(corrupted), "application/pdf"),
                "key_file": ("key.json", BytesIO(key_file), "application/json")
            }
        )

        # Should fail gracefully
        assert decrypt_response.status_code == 400

    def test_corrupted_key_file(self, sample_pdf_file):
        """Test handling of corrupted key file"""
        import base64

        # First encrypt to get valid encrypted file
        encrypt_response = client.post(
            "/api/encrypt",
            files={"file": ("test.pdf", sample_pdf_file, "application/pdf")}
        )
        encrypt_data = encrypt_response.json()
        encrypted_pdf = base64.b64decode(encrypt_data['encrypted_file'])

        # Try to decrypt with corrupted key
        corrupted_key = b'{"invalid": "key file"}'

        decrypt_response = client.post(
            "/api/decrypt",
            files={
                "encrypted_file": ("encrypted.pdf", BytesIO(encrypted_pdf), "application/pdf"),
                "key_file": ("key.json", BytesIO(corrupted_key), "application/json")
            }
        )

        # Should fail gracefully
        assert decrypt_response.status_code in [400, 500]
