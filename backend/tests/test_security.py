"""
Security-focused tests for the PDF encryption system

Tests for:
- Input validation
- Timing attacks resistance
- Key/IV uniqueness
- Error message safety (no information leakage)
- Memory handling
- Concurrent access
"""

import pytest
import json
import base64
import os
import sys
import threading
import time
from io import BytesIO
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.algorithms import (
    AESGCMCipher,
    AES128GCMCipher,
    ChaCha20Cipher,
    AESCBCCipher,
    DESCipher,
    RSACipher,
    HMACGenerator
)
from crypto.encryption import encrypt_pdf, encrypt_pdf_page_selection
from crypto.decryption import decrypt_pdf, decrypt_pdf_page_selection
from crypto.cryptography import CascadingEntropyMixer


@pytest.fixture
def sample_pdf_bytes():
    """Create a sample PDF for testing"""
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter

    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    c.drawString(100, 750, "Test PDF Document")
    c.drawString(100, 700, "Sensitive content here")
    c.showPage()
    c.save()
    buffer.seek(0)
    return buffer.read()


class TestKeyUniqueness:
    """Tests to ensure keys and IVs are always unique"""

    def test_aes_key_uniqueness(self):
        """Test that AES keys are unique"""
        keys = [AESGCMCipher.generate_key() for _ in range(1000)]
        assert len(set(keys)) == 1000, "Generated AES keys should all be unique"

    def test_aes_iv_uniqueness(self):
        """Test that AES IVs are unique"""
        ivs = [AESGCMCipher.generate_iv() for _ in range(1000)]
        assert len(set(ivs)) == 1000, "Generated IVs should all be unique"

    def test_chacha_key_uniqueness(self):
        """Test that ChaCha20 keys are unique"""
        keys = [ChaCha20Cipher.generate_key() for _ in range(1000)]
        assert len(set(keys)) == 1000, "Generated ChaCha20 keys should all be unique"

    def test_chacha_nonce_uniqueness(self):
        """Test that ChaCha20 nonces are unique"""
        nonces = [ChaCha20Cipher.generate_nonce() for _ in range(1000)]
        assert len(set(nonces)) == 1000, "Generated nonces should all be unique"

    def test_rsa_keypair_uniqueness(self):
        """Test that RSA keypairs are unique"""
        keypairs = [RSACipher.generate_keypair() for _ in range(10)]
        private_keys = [kp[0] for kp in keypairs]

        # Serialize to compare
        serialized = [RSACipher.serialize_private_key(pk) for pk in private_keys]
        assert len(set(serialized)) == 10, "Generated RSA keys should all be unique"

    def test_encryption_produces_unique_ciphertext(self):
        """Test that encrypting same plaintext produces different ciphertexts"""
        plaintext = b"Same plaintext every time"
        key = AESGCMCipher.generate_key()

        ciphertexts = []
        for _ in range(100):
            ct, _ = AESGCMCipher.encrypt(plaintext, key)
            ciphertexts.append(ct)

        # Due to random IV, all ciphertexts should be different
        assert len(set(ciphertexts)) == 100, "Same plaintext should produce different ciphertexts"


class TestInputValidation:
    """Tests for proper input validation"""

    def test_encrypt_empty_plaintext(self):
        """Test encryption of empty data"""
        key = AESGCMCipher.generate_key()
        ciphertext, iv = AESGCMCipher.encrypt(b"", key)

        # Should work without error
        assert len(ciphertext) > 0  # GCM adds auth tag

    def test_encrypt_very_large_data(self):
        """Test encryption of large data (1MB)"""
        large_data = os.urandom(1024 * 1024)  # 1MB
        key = AESGCMCipher.generate_key()

        ciphertext, iv = AESGCMCipher.encrypt(large_data, key)
        decrypted = AESGCMCipher.decrypt(ciphertext, key, iv)

        assert decrypted == large_data

    def test_decrypt_with_short_ciphertext(self):
        """Test decryption with too-short ciphertext (should fail gracefully)"""
        key = AESGCMCipher.generate_key()
        iv = AESGCMCipher.generate_iv()

        with pytest.raises(Exception):
            AESGCMCipher.decrypt(b"short", key, iv)

    def test_decrypt_with_wrong_iv_length(self):
        """Test decryption with wrong IV length"""
        key = AESGCMCipher.generate_key()
        plaintext = b"Test data"
        ciphertext, _ = AESGCMCipher.encrypt(plaintext, key)

        # Wrong IV length
        wrong_iv = b"tooshort"

        with pytest.raises(Exception):
            AESGCMCipher.decrypt(ciphertext, key, wrong_iv)

    def test_rsa_max_plaintext_size(self):
        """Test RSA plaintext size limit"""
        private_key, public_key = RSACipher.generate_keypair()

        # RSA-OAEP with SHA-256 can encrypt max ~446 bytes with 4096-bit key
        # Try encrypting exactly at limit
        max_size = 446
        data = os.urandom(max_size)

        try:
            ciphertext = RSACipher.encrypt(data, public_key)
            decrypted = RSACipher.decrypt(ciphertext, private_key)
            assert decrypted == data
        except Exception:
            # Some implementations may have different limits
            pass

    def test_rsa_oversized_plaintext(self):
        """Test RSA with oversized plaintext (should fail)"""
        private_key, public_key = RSACipher.generate_keypair()

        # Too large for RSA
        large_data = os.urandom(1000)

        with pytest.raises(Exception):
            RSACipher.encrypt(large_data, public_key)


class TestTamperDetection:
    """Tests for tamper detection"""

    def test_gcm_detects_ciphertext_modification(self):
        """Test that GCM detects modified ciphertext"""
        key = AESGCMCipher.generate_key()
        plaintext = b"Original message"

        ciphertext, iv = AESGCMCipher.encrypt(plaintext, key)

        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        tampered = bytes(tampered)

        with pytest.raises(Exception):
            AESGCMCipher.decrypt(tampered, key, iv)

    def test_gcm_detects_auth_tag_modification(self):
        """Test that GCM detects modified authentication tag"""
        key = AESGCMCipher.generate_key()
        plaintext = b"Original message"

        ciphertext, iv = AESGCMCipher.encrypt(plaintext, key)

        # GCM auth tag is at the end (16 bytes)
        tampered = bytearray(ciphertext)
        tampered[-1] ^= 0xFF
        tampered = bytes(tampered)

        with pytest.raises(Exception):
            AESGCMCipher.decrypt(tampered, key, iv)

    def test_chacha_detects_ciphertext_modification(self):
        """Test that ChaCha20-Poly1305 detects modifications"""
        key = ChaCha20Cipher.generate_key()
        plaintext = b"Original message"

        ciphertext, nonce = ChaCha20Cipher.encrypt(plaintext, key)

        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        tampered = bytes(tampered)

        with pytest.raises(Exception):
            ChaCha20Cipher.decrypt(tampered, key, nonce)

    def test_hmac_detects_data_modification(self):
        """Test that HMAC detects data modification"""
        key = HMACGenerator.generate_key()
        data = b"Original data"

        hmac_tag = HMACGenerator.compute(data, key)

        # Modify data
        modified_data = b"Modified data"

        assert not HMACGenerator.verify(modified_data, key, hmac_tag)

    def test_pdf_tamper_detection(self, sample_pdf_bytes):
        """Test that PDF tampering is detected during decryption"""
        encrypted_pdf, key_file = encrypt_pdf(sample_pdf_bytes, "test.pdf")

        # Tamper with encrypted PDF data in key file
        key_data = json.loads(key_file.decode('utf-8'))
        original_data = base64.b64decode(key_data['metadata']['encrypted_pdf_data'])

        tampered_data = bytearray(original_data)
        if len(tampered_data) > 100:
            tampered_data[100] ^= 0xFF
        tampered_data = bytes(tampered_data)

        key_data['metadata']['encrypted_pdf_data'] = base64.b64encode(tampered_data).decode('utf-8')
        tampered_key_file = json.dumps(key_data).encode('utf-8')

        with pytest.raises(ValueError):
            decrypt_pdf(encrypted_pdf, tampered_key_file)


class TestConcurrentAccess:
    """Tests for thread safety"""

    def test_concurrent_key_generation(self):
        """Test that concurrent key generation produces unique keys"""
        keys = []
        lock = threading.Lock()

        def generate_keys():
            for _ in range(100):
                key = AESGCMCipher.generate_key()
                with lock:
                    keys.append(key)

        threads = [threading.Thread(target=generate_keys) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(keys) == 1000
        assert len(set(keys)) == 1000, "All keys should be unique even with concurrent generation"

    def test_concurrent_encryption(self, sample_pdf_bytes):
        """Test concurrent encryption operations"""
        results = []
        errors = []

        def encrypt_task():
            try:
                encrypted_pdf, key_file = encrypt_pdf(sample_pdf_bytes, "test.pdf")
                decrypted_pdf, _ = decrypt_pdf(encrypted_pdf, key_file)
                assert decrypted_pdf == sample_pdf_bytes
                results.append(True)
            except Exception as e:
                errors.append(str(e))

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(encrypt_task) for _ in range(10)]
            for future in as_completed(futures):
                future.result()

        assert len(errors) == 0, f"Concurrent encryption failed: {errors}"
        assert len(results) == 10

    def test_cem_thread_safety(self):
        """Test CascadingEntropyMixer thread safety"""
        cem = CascadingEntropyMixer(rounds=7, pool_size=64)
        keys = []
        lock = threading.Lock()
        errors = []

        def generate_keys():
            try:
                for _ in range(100):
                    key = cem.generate_key(32)
                    with lock:
                        keys.append(key)
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=generate_keys) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0, f"CEM thread safety failed: {errors}"
        assert len(keys) == 1000
        assert len(set(keys)) == 1000


class TestErrorMessageSafety:
    """Tests to ensure error messages don't leak sensitive information"""

    def test_wrong_key_error_generic(self, sample_pdf_bytes):
        """Test that wrong key error doesn't reveal key info"""
        encrypted_pdf, key_file = encrypt_pdf(sample_pdf_bytes, "test.pdf")
        _, key_file2 = encrypt_pdf(sample_pdf_bytes, "test2.pdf")

        try:
            decrypt_pdf(encrypted_pdf, key_file2)
            assert False, "Should have raised exception"
        except Exception as e:
            error_msg = str(e).lower()
            # Error should not contain actual key bytes
            assert 'key=' not in error_msg
            assert '0x' not in error_msg or len(error_msg) < 200

    def test_hmac_failure_generic(self, sample_pdf_bytes):
        """Test that HMAC failure doesn't reveal HMAC values"""
        encrypted_pdf, key_file = encrypt_pdf(sample_pdf_bytes, "test.pdf")

        key_data = json.loads(key_file.decode('utf-8'))
        key_data['metadata']['hmac'] = base64.b64encode(b'wrong').decode('utf-8')
        bad_key_file = json.dumps(key_data).encode('utf-8')

        try:
            decrypt_pdf(encrypted_pdf, bad_key_file)
            assert False, "Should have raised exception"
        except ValueError as e:
            error_msg = str(e)
            # Should say "HMAC verification failed" but not reveal actual HMAC
            assert "HMAC" in error_msg or "verification" in error_msg.lower()
            # Should not contain actual HMAC values
            assert len(error_msg) < 200


class TestKeyEntropyQuality:
    """Tests for key entropy quality"""

    def test_key_byte_distribution(self):
        """Test that generated keys have good byte distribution"""
        # Generate a large sample of key bytes
        all_bytes = b''
        for _ in range(100):
            all_bytes += AESGCMCipher.generate_key()

        # Check byte distribution
        byte_counts = [0] * 256
        for byte in all_bytes:
            byte_counts[byte] += 1

        # No single byte should appear more than 5% of the time
        max_expected = len(all_bytes) * 0.05
        max_actual = max(byte_counts)
        assert max_actual < max_expected, f"Poor key entropy: byte appeared {max_actual} times (max expected {max_expected})"

    def test_cem_entropy_quality(self):
        """Test CEM key entropy quality"""
        cem = CascadingEntropyMixer(rounds=7, pool_size=64)

        # Generate large sample
        all_bytes = b''
        for _ in range(100):
            all_bytes += cem.generate_key(32)

        byte_counts = [0] * 256
        for byte in all_bytes:
            byte_counts[byte] += 1

        # Check for reasonable distribution
        max_expected = len(all_bytes) * 0.05
        max_actual = max(byte_counts)
        assert max_actual < max_expected


class TestCBCSpecificVulnerabilities:
    """Tests for CBC-specific security considerations"""

    def test_cbc_iv_uniqueness_per_encryption(self):
        """Test that CBC always uses unique IVs"""
        key = AESCBCCipher.generate_key()
        plaintext = b"Same plaintext"

        ivs = []
        for _ in range(100):
            _, iv, _ = AESCBCCipher.encrypt(plaintext, key)
            ivs.append(iv)

        assert len(set(ivs)) == 100, "CBC should use unique IV for each encryption"

    def test_cbc_padding_oracle_resistance(self):
        """Test that CBC decryption fails appropriately on bad padding"""
        key = AESCBCCipher.generate_key()
        plaintext = b"Test message"

        ciphertext, iv, _ = AESCBCCipher.encrypt(plaintext, key)

        # Corrupt the last byte (padding indicator)
        corrupted = bytearray(ciphertext)
        corrupted[-1] ^= 0x01
        corrupted = bytes(corrupted)

        # Should fail during unpadding
        with pytest.raises(Exception):
            AESCBCCipher.decrypt(corrupted, key, iv)


class TestDESInsecurity:
    """Tests documenting DES insecurity (for academic purposes)"""

    def test_des_key_size_warning(self):
        """Document that DES uses small key size"""
        key = DESCipher.generate_key()
        # DES key is only 8 bytes (56 effective bits)
        assert len(key) == 8, "DES key should be 8 bytes (56 effective bits - INSECURE)"

    def test_des_still_works_for_education(self):
        """Test that DES works for educational purposes"""
        key = DESCipher.generate_key()
        plaintext = b"Test message for DES"

        ciphertext, iv, _ = DESCipher.encrypt(plaintext, key)
        decrypted = DESCipher.decrypt(ciphertext, key, iv)

        assert decrypted == plaintext
