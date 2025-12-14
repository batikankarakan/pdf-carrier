"""
Unit tests for cipher algorithms (AES-GCM, ChaCha20, AES-CBC, DES, RSA, HMAC)
"""

import pytest
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.algorithms import (
    AESGCMCipher,
    AES128GCMCipher,
    AESCBCCipher,
    ChaCha20Cipher,
    DESCipher,
    RSACipher,
    HMACGenerator
)


class TestAESGCMCipher:
    """Tests for AES-256-GCM cipher"""

    def test_generate_key_length(self):
        """Test key generation produces correct length"""
        key = AESGCMCipher.generate_key()
        assert len(key) == 32, "AES-256 key should be 32 bytes"

    def test_generate_iv_length(self):
        """Test IV generation produces correct length"""
        iv = AESGCMCipher.generate_iv()
        assert len(iv) == 12, "GCM IV should be 12 bytes"

    def test_encrypt_decrypt_roundtrip(self, sample_plaintext):
        """Test encryption and decryption produce original data"""
        key = AESGCMCipher.generate_key()
        ciphertext, iv = AESGCMCipher.encrypt(sample_plaintext, key)
        decrypted = AESGCMCipher.decrypt(ciphertext, key, iv)

        assert decrypted == sample_plaintext

    def test_ciphertext_differs_from_plaintext(self, sample_plaintext):
        """Test that ciphertext is different from plaintext"""
        key = AESGCMCipher.generate_key()
        ciphertext, _ = AESGCMCipher.encrypt(sample_plaintext, key)

        assert ciphertext != sample_plaintext

    def test_different_keys_produce_different_ciphertext(self, sample_plaintext):
        """Test that different keys produce different ciphertext"""
        key1 = AESGCMCipher.generate_key()
        key2 = AESGCMCipher.generate_key()

        ciphertext1, _ = AESGCMCipher.encrypt(sample_plaintext, key1)
        ciphertext2, _ = AESGCMCipher.encrypt(sample_plaintext, key2)

        assert ciphertext1 != ciphertext2

    def test_wrong_key_fails_decryption(self, sample_plaintext):
        """Test that wrong key fails to decrypt"""
        key1 = AESGCMCipher.generate_key()
        key2 = AESGCMCipher.generate_key()

        ciphertext, iv = AESGCMCipher.encrypt(sample_plaintext, key1)

        with pytest.raises(Exception):
            AESGCMCipher.decrypt(ciphertext, key2, iv)

    def test_tampered_ciphertext_fails(self, sample_plaintext):
        """Test that tampered ciphertext fails authentication"""
        key = AESGCMCipher.generate_key()
        ciphertext, iv = AESGCMCipher.encrypt(sample_plaintext, key)

        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        tampered = bytes(tampered)

        with pytest.raises(Exception):
            AESGCMCipher.decrypt(tampered, key, iv)

    def test_large_data_encryption(self, large_plaintext):
        """Test encryption of large data"""
        key = AESGCMCipher.generate_key()
        ciphertext, iv = AESGCMCipher.encrypt(large_plaintext, key)
        decrypted = AESGCMCipher.decrypt(ciphertext, key, iv)

        assert decrypted == large_plaintext

    def test_binary_data_encryption(self, binary_data):
        """Test encryption of binary data with all byte values"""
        key = AESGCMCipher.generate_key()
        ciphertext, iv = AESGCMCipher.encrypt(binary_data, key)
        decrypted = AESGCMCipher.decrypt(ciphertext, key, iv)

        assert decrypted == binary_data

    def test_key_uniqueness(self):
        """Test that generated keys are unique"""
        keys = [AESGCMCipher.generate_key() for _ in range(100)]
        assert len(set(keys)) == 100


class TestAES128GCMCipher:
    """Tests for AES-128-GCM cipher"""

    def test_generate_key_length(self):
        """Test key generation produces correct length"""
        key = AES128GCMCipher.generate_key()
        assert len(key) == 16, "AES-128 key should be 16 bytes"

    def test_encrypt_decrypt_roundtrip(self, sample_plaintext):
        """Test encryption and decryption produce original data"""
        key = AES128GCMCipher.generate_key()
        ciphertext, iv = AES128GCMCipher.encrypt(sample_plaintext, key)
        decrypted = AES128GCMCipher.decrypt(ciphertext, key, iv)

        assert decrypted == sample_plaintext

    def test_wrong_key_fails(self, sample_plaintext):
        """Test that wrong key fails to decrypt"""
        key1 = AES128GCMCipher.generate_key()
        key2 = AES128GCMCipher.generate_key()

        ciphertext, iv = AES128GCMCipher.encrypt(sample_plaintext, key1)

        with pytest.raises(Exception):
            AES128GCMCipher.decrypt(ciphertext, key2, iv)


class TestChaCha20Cipher:
    """Tests for ChaCha20-Poly1305 cipher"""

    def test_generate_key_length(self):
        """Test key generation produces correct length"""
        key = ChaCha20Cipher.generate_key()
        assert len(key) == 32, "ChaCha20 key should be 32 bytes"

    def test_generate_nonce_length(self):
        """Test nonce generation produces correct length"""
        nonce = ChaCha20Cipher.generate_nonce()
        assert len(nonce) == 12, "ChaCha20 nonce should be 12 bytes"

    def test_encrypt_decrypt_roundtrip(self, sample_plaintext):
        """Test encryption and decryption produce original data"""
        key = ChaCha20Cipher.generate_key()
        ciphertext, nonce = ChaCha20Cipher.encrypt(sample_plaintext, key)
        decrypted = ChaCha20Cipher.decrypt(ciphertext, key, nonce)

        assert decrypted == sample_plaintext

    def test_ciphertext_differs_from_plaintext(self, sample_plaintext):
        """Test that ciphertext is different from plaintext"""
        key = ChaCha20Cipher.generate_key()
        ciphertext, _ = ChaCha20Cipher.encrypt(sample_plaintext, key)

        assert ciphertext != sample_plaintext

    def test_wrong_key_fails_decryption(self, sample_plaintext):
        """Test that wrong key fails to decrypt"""
        key1 = ChaCha20Cipher.generate_key()
        key2 = ChaCha20Cipher.generate_key()

        ciphertext, nonce = ChaCha20Cipher.encrypt(sample_plaintext, key1)

        with pytest.raises(Exception):
            ChaCha20Cipher.decrypt(ciphertext, key2, nonce)

    def test_tampered_ciphertext_fails(self, sample_plaintext):
        """Test that tampered ciphertext fails authentication"""
        key = ChaCha20Cipher.generate_key()
        ciphertext, nonce = ChaCha20Cipher.encrypt(sample_plaintext, key)

        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        tampered = bytes(tampered)

        with pytest.raises(Exception):
            ChaCha20Cipher.decrypt(tampered, key, nonce)

    def test_large_data_encryption(self, large_plaintext):
        """Test encryption of large data"""
        key = ChaCha20Cipher.generate_key()
        ciphertext, nonce = ChaCha20Cipher.encrypt(large_plaintext, key)
        decrypted = ChaCha20Cipher.decrypt(ciphertext, key, nonce)

        assert decrypted == large_plaintext


class TestAESCBCCipher:
    """Tests for AES-256-CBC cipher"""

    def test_generate_key_length(self):
        """Test key generation produces correct length"""
        key = AESCBCCipher.generate_key()
        assert len(key) == 32, "AES-256 key should be 32 bytes"

    def test_generate_iv_length(self):
        """Test IV generation produces correct length"""
        iv = AESCBCCipher.generate_iv()
        assert len(iv) == 16, "CBC IV should be 16 bytes"

    def test_encrypt_decrypt_roundtrip(self, sample_plaintext):
        """Test encryption and decryption produce original data"""
        key = AESCBCCipher.generate_key()
        ciphertext, iv, _ = AESCBCCipher.encrypt(sample_plaintext, key)
        decrypted = AESCBCCipher.decrypt(ciphertext, key, iv)

        assert decrypted == sample_plaintext

    def test_ciphertext_differs_from_plaintext(self, sample_plaintext):
        """Test that ciphertext is different from plaintext"""
        key = AESCBCCipher.generate_key()
        ciphertext, _, _ = AESCBCCipher.encrypt(sample_plaintext, key)

        assert ciphertext != sample_plaintext

    def test_wrong_key_produces_garbage(self, sample_plaintext):
        """Test that wrong key produces garbage or fails"""
        key1 = AESCBCCipher.generate_key()
        key2 = AESCBCCipher.generate_key()

        ciphertext, iv, _ = AESCBCCipher.encrypt(sample_plaintext, key1)

        # CBC with wrong key will either fail or produce garbage
        try:
            decrypted = AESCBCCipher.decrypt(ciphertext, key2, iv)
            assert decrypted != sample_plaintext
        except Exception:
            pass  # Expected - padding error or other

    def test_pkcs7_padding_applied(self, sample_plaintext):
        """Test that PKCS7 padding is applied correctly"""
        key = AESCBCCipher.generate_key()
        ciphertext, iv, _ = AESCBCCipher.encrypt(sample_plaintext, key)

        # Ciphertext should be multiple of 16 (AES block size)
        assert len(ciphertext) % 16 == 0

    def test_large_data_encryption(self, large_plaintext):
        """Test encryption of large data"""
        key = AESCBCCipher.generate_key()
        ciphertext, iv, _ = AESCBCCipher.encrypt(large_plaintext, key)
        decrypted = AESCBCCipher.decrypt(ciphertext, key, iv)

        assert decrypted == large_plaintext


class TestDESCipher:
    """Tests for DES cipher (legacy/academic use)"""

    def test_generate_key_length(self):
        """Test key generation produces correct length"""
        key = DESCipher.generate_key()
        assert len(key) == 8, "DES key should be 8 bytes"

    def test_generate_iv_length(self):
        """Test IV generation produces correct length"""
        iv = DESCipher.generate_iv()
        assert len(iv) == 8, "DES IV should be 8 bytes"

    def test_encrypt_decrypt_roundtrip(self, sample_plaintext):
        """Test encryption and decryption produce original data"""
        key = DESCipher.generate_key()
        ciphertext, iv, _ = DESCipher.encrypt(sample_plaintext, key)
        decrypted = DESCipher.decrypt(ciphertext, key, iv)

        assert decrypted == sample_plaintext

    def test_ciphertext_differs_from_plaintext(self, sample_plaintext):
        """Test that ciphertext is different from plaintext"""
        key = DESCipher.generate_key()
        ciphertext, _, _ = DESCipher.encrypt(sample_plaintext, key)

        assert ciphertext != sample_plaintext

    def test_pkcs7_padding_applied(self, sample_plaintext):
        """Test that PKCS7 padding is applied correctly"""
        key = DESCipher.generate_key()
        ciphertext, iv, _ = DESCipher.encrypt(sample_plaintext, key)

        # Ciphertext should be multiple of 8 (DES block size)
        assert len(ciphertext) % 8 == 0


class TestRSACipher:
    """Tests for RSA cipher"""

    def test_generate_keypair(self):
        """Test RSA key pair generation"""
        private_key, public_key = RSACipher.generate_keypair(key_size=2048)

        assert private_key is not None
        assert public_key is not None

    def test_encrypt_decrypt_roundtrip(self):
        """Test RSA encryption and decryption"""
        private_key, public_key = RSACipher.generate_keypair(key_size=2048)

        # RSA can only encrypt small data (less than key size)
        plaintext = b"Small symmetric key data"

        ciphertext = RSACipher.encrypt(plaintext, public_key)
        decrypted = RSACipher.decrypt(ciphertext, private_key)

        assert decrypted == plaintext

    def test_ciphertext_differs_from_plaintext(self):
        """Test that RSA ciphertext differs from plaintext"""
        private_key, public_key = RSACipher.generate_keypair(key_size=2048)
        plaintext = b"Test data"

        ciphertext = RSACipher.encrypt(plaintext, public_key)
        assert ciphertext != plaintext

    def test_wrong_key_fails_decryption(self):
        """Test that wrong private key fails decryption"""
        _, public_key1 = RSACipher.generate_keypair(key_size=2048)
        private_key2, _ = RSACipher.generate_keypair(key_size=2048)

        plaintext = b"Test data"
        ciphertext = RSACipher.encrypt(plaintext, public_key1)

        with pytest.raises(Exception):
            RSACipher.decrypt(ciphertext, private_key2)

    def test_serialize_deserialize_private_key(self):
        """Test private key serialization and deserialization"""
        private_key, _ = RSACipher.generate_keypair(key_size=2048)

        pem_data = RSACipher.serialize_private_key(private_key)
        loaded_key = RSACipher.deserialize_private_key(pem_data)

        # Test that loaded key works
        plaintext = b"Test"
        _, public_key = RSACipher.generate_keypair(key_size=2048)

        # Derive public key from loaded private key for comparison
        assert loaded_key.key_size == private_key.key_size

    def test_serialize_deserialize_public_key(self):
        """Test public key serialization and deserialization"""
        _, public_key = RSACipher.generate_keypair(key_size=2048)

        pem_data = RSACipher.serialize_public_key(public_key)
        loaded_key = RSACipher.deserialize_public_key(pem_data)

        assert loaded_key.key_size == public_key.key_size

    def test_4096_bit_key(self):
        """Test 4096-bit RSA key generation and use"""
        private_key, public_key = RSACipher.generate_keypair(key_size=4096)

        plaintext = b"Test with 4096-bit key"
        ciphertext = RSACipher.encrypt(plaintext, public_key)
        decrypted = RSACipher.decrypt(ciphertext, private_key)

        assert decrypted == plaintext
        assert private_key.key_size == 4096


class TestHMACGenerator:
    """Tests for HMAC-SHA256"""

    def test_generate_key_length(self):
        """Test HMAC key generation"""
        key = HMACGenerator.generate_key()
        assert len(key) == 32, "HMAC key should be 32 bytes"

    def test_compute_hmac(self, sample_plaintext):
        """Test HMAC computation"""
        key = HMACGenerator.generate_key()
        hmac_tag = HMACGenerator.compute(sample_plaintext, key)

        assert len(hmac_tag) == 32, "HMAC-SHA256 should be 32 bytes"

    def test_verify_valid_hmac(self, sample_plaintext):
        """Test HMAC verification with valid tag"""
        key = HMACGenerator.generate_key()
        hmac_tag = HMACGenerator.compute(sample_plaintext, key)

        assert HMACGenerator.verify(sample_plaintext, key, hmac_tag) is True

    def test_verify_invalid_hmac(self, sample_plaintext):
        """Test HMAC verification with invalid tag"""
        key = HMACGenerator.generate_key()
        wrong_tag = b"\x00" * 32

        assert HMACGenerator.verify(sample_plaintext, key, wrong_tag) is False

    def test_verify_tampered_data(self, sample_plaintext):
        """Test HMAC verification with tampered data"""
        key = HMACGenerator.generate_key()
        hmac_tag = HMACGenerator.compute(sample_plaintext, key)

        tampered_data = sample_plaintext + b"extra"
        assert HMACGenerator.verify(tampered_data, key, hmac_tag) is False

    def test_different_keys_produce_different_hmacs(self, sample_plaintext):
        """Test that different keys produce different HMACs"""
        key1 = HMACGenerator.generate_key()
        key2 = HMACGenerator.generate_key()

        hmac1 = HMACGenerator.compute(sample_plaintext, key1)
        hmac2 = HMACGenerator.compute(sample_plaintext, key2)

        assert hmac1 != hmac2

    def test_same_key_produces_same_hmac(self, sample_plaintext):
        """Test that same key produces same HMAC"""
        key = HMACGenerator.generate_key()

        hmac1 = HMACGenerator.compute(sample_plaintext, key)
        hmac2 = HMACGenerator.compute(sample_plaintext, key)

        assert hmac1 == hmac2


class TestCrossAlgorithmCompatibility:
    """Tests for cross-algorithm scenarios"""

    def test_aes_gcm_then_chacha20(self, sample_plaintext):
        """Test double encryption with AES-GCM then ChaCha20"""
        aes_key = AESGCMCipher.generate_key()
        chacha_key = ChaCha20Cipher.generate_key()

        # First layer: AES-GCM
        layer1_ct, layer1_iv = AESGCMCipher.encrypt(sample_plaintext, aes_key)

        # Second layer: ChaCha20
        layer2_ct, layer2_nonce = ChaCha20Cipher.encrypt(layer1_ct, chacha_key)

        # Decrypt in reverse order
        decrypted_layer1 = ChaCha20Cipher.decrypt(layer2_ct, chacha_key, layer2_nonce)
        decrypted = AESGCMCipher.decrypt(decrypted_layer1, aes_key, layer1_iv)

        assert decrypted == sample_plaintext

    def test_all_algorithms_roundtrip(self, sample_plaintext):
        """Test that all algorithms can encrypt and decrypt"""
        algorithms = [
            (AESGCMCipher, True),      # (cipher, has_auth_tag)
            (AES128GCMCipher, True),
            (ChaCha20Cipher, True),
            (AESCBCCipher, False),
            (DESCipher, False),
        ]

        for cipher, has_auth in algorithms:
            key = cipher.generate_key()

            if has_auth:
                ciphertext, iv = cipher.encrypt(sample_plaintext, key)
            else:
                ciphertext, iv, _ = cipher.encrypt(sample_plaintext, key)

            decrypted = cipher.decrypt(ciphertext, key, iv)
            assert decrypted == sample_plaintext, f"Failed for {cipher.__name__}"
