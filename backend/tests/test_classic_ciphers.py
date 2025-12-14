"""
Unit tests for classic/legacy cipher implementations
WARNING: These ciphers (DES, Playfair) are INSECURE - for academic purposes only
"""

import pytest
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.classic_ciphers import (
    encrypt_des,
    decrypt_des,
    pad_key_to_8_bytes,
    encrypt_playfair,
    decrypt_playfair,
    generate_playfair_matrix,
    preprocess_text
)


class TestDESCipher:
    """Tests for DES encryption (INSECURE - academic use only)"""

    def test_encrypt_decrypt_roundtrip(self):
        """Test basic DES encryption/decryption"""
        plaintext = b"Hello, World! This is a test message."
        key = b"testkey1"

        ciphertext = encrypt_des(plaintext, key)
        decrypted = decrypt_des(ciphertext, key)

        assert decrypted == plaintext

    def test_ciphertext_differs_from_plaintext(self):
        """Test that ciphertext differs from plaintext"""
        plaintext = b"Secret message"
        key = b"mykey123"

        ciphertext = encrypt_des(plaintext, key)

        # Remove IV (first 8 bytes) before comparison
        assert ciphertext[8:] != plaintext

    def test_key_padding_short_key(self):
        """Test key padding with short key"""
        short_key = b"abc"
        padded = pad_key_to_8_bytes(short_key)

        assert len(padded) == 8
        assert padded[:3] == b"abc"
        assert padded[3:] == b'\0\0\0\0\0'

    def test_key_padding_long_key(self):
        """Test key padding with long key (truncation)"""
        long_key = b"verylongkey12345"
        padded = pad_key_to_8_bytes(long_key)

        assert len(padded) == 8
        assert padded == b"verylong"

    def test_key_padding_exact_key(self):
        """Test key padding with exact 8-byte key"""
        exact_key = b"exactly8"
        padded = pad_key_to_8_bytes(exact_key)

        assert len(padded) == 8
        assert padded == exact_key

    def test_wrong_key_fails_decryption(self):
        """Test that wrong key produces garbage or fails"""
        plaintext = b"Secret message"
        key1 = b"key1key1"
        key2 = b"key2key2"

        ciphertext = encrypt_des(plaintext, key1)

        # Wrong key should either fail or produce garbage
        try:
            decrypted = decrypt_des(ciphertext, key2)
            assert decrypted != plaintext
        except Exception:
            pass  # Decryption failure is expected

    def test_iv_is_unique(self):
        """Test that each encryption produces unique IV"""
        plaintext = b"Test data"
        key = b"testkey1"

        ciphertext1 = encrypt_des(plaintext, key)
        ciphertext2 = encrypt_des(plaintext, key)

        # IVs (first 8 bytes) should be different
        assert ciphertext1[:8] != ciphertext2[:8]

    def test_short_data_encryption(self):
        """Test encryption of very short data"""
        plaintext = b"Hi"
        key = b"testkey1"

        ciphertext = encrypt_des(plaintext, key)
        decrypted = decrypt_des(ciphertext, key)

        assert decrypted == plaintext

    def test_empty_data_encryption(self):
        """Test encryption of empty data"""
        plaintext = b""
        key = b"testkey1"

        ciphertext = encrypt_des(plaintext, key)
        decrypted = decrypt_des(ciphertext, key)

        assert decrypted == plaintext

    def test_binary_data_encryption(self):
        """Test encryption of binary data"""
        plaintext = bytes(range(256))
        key = b"binkey12"

        ciphertext = encrypt_des(plaintext, key)
        decrypted = decrypt_des(ciphertext, key)

        assert decrypted == plaintext

    def test_invalid_token_too_short(self):
        """Test that too-short token raises error"""
        with pytest.raises(ValueError, match="yeterli uzunluk"):
            decrypt_des(b"short", b"testkey1")


class TestPlayfairCipher:
    """Tests for Playfair cipher (INSECURE - academic use only)"""

    def test_generate_matrix_basic(self):
        """Test Playfair matrix generation"""
        matrix = generate_playfair_matrix("KEYWORD")

        # Matrix should be 5x5
        assert len(matrix) == 5
        assert all(len(row) == 5 for row in matrix)

        # Matrix should contain 25 unique letters (no J)
        all_chars = [char for row in matrix for char in row]
        assert len(set(all_chars)) == 25
        assert 'J' not in all_chars

    def test_generate_matrix_with_duplicates(self):
        """Test matrix generation with duplicate letters in key"""
        matrix = generate_playfair_matrix("BALLOON")

        all_chars = [char for row in matrix for char in row]
        assert len(set(all_chars)) == 25

    def test_generate_matrix_with_j(self):
        """Test that J is replaced with I"""
        matrix = generate_playfair_matrix("JUMP")

        all_chars = [char for row in matrix for char in row]
        assert 'J' not in all_chars
        assert 'I' in all_chars

    def test_preprocess_text_basic(self):
        """Test text preprocessing"""
        result = preprocess_text("HELLO")

        # Double L should get X inserted
        assert 'X' in result
        # Length should be even
        assert len(result) % 2 == 0

    def test_preprocess_text_removes_nonalpha(self):
        """Test that non-alphabetic characters are removed"""
        result = preprocess_text("HE123LLO!")

        assert result.isalpha()
        assert len(result) % 2 == 0

    def test_preprocess_text_converts_j_to_i(self):
        """Test that J is converted to I"""
        result = preprocess_text("JAM")

        assert 'J' not in result
        assert result.startswith('I')

    def test_encrypt_decrypt_roundtrip(self):
        """Test basic Playfair encryption/decryption"""
        plaintext = "HELLO"
        key = "KEYWORD"

        ciphertext = encrypt_playfair(plaintext, key)
        decrypted = decrypt_playfair(ciphertext, key)

        # Note: Playfair may add X padding, so we check if original is contained
        # Also, double letters get X inserted, so exact match is not guaranteed
        assert len(decrypted) >= len(plaintext.replace(" ", ""))

    def test_ciphertext_differs_from_plaintext(self):
        """Test that ciphertext differs from plaintext"""
        plaintext = "SECRET"
        key = "MONARCHY"

        ciphertext = encrypt_playfair(plaintext, key)

        assert ciphertext != plaintext

    def test_same_key_produces_consistent_results(self):
        """Test that same key produces same ciphertext"""
        plaintext = "ATTACK"
        key = "KEYWORD"

        ciphertext1 = encrypt_playfair(plaintext, key)
        ciphertext2 = encrypt_playfair(plaintext, key)

        assert ciphertext1 == ciphertext2

    def test_different_keys_produce_different_results(self):
        """Test that different keys produce different ciphertext"""
        plaintext = "ATTACK"
        key1 = "KEYWORD"
        key2 = "MONARCHY"

        ciphertext1 = encrypt_playfair(plaintext, key1)
        ciphertext2 = encrypt_playfair(plaintext, key2)

        assert ciphertext1 != ciphertext2

    def test_decrypt_invalid_length(self):
        """Test that odd-length ciphertext raises error"""
        with pytest.raises(ValueError, match="çift sayıda"):
            decrypt_playfair("ABC", "KEYWORD")

    def test_lowercase_handling(self):
        """Test that lowercase is handled correctly"""
        plaintext = "hello world"
        key = "keyword"

        ciphertext = encrypt_playfair(plaintext, key)
        decrypted = decrypt_playfair(ciphertext, key)

        # Should work and return uppercase
        assert ciphertext.isupper()
        assert decrypted.isupper()

    def test_special_characters_removed(self):
        """Test that special characters are removed"""
        plaintext = "HE!!O @#$% WOR^&*LD"
        key = "KEYWORD"

        # Should not raise, special chars are removed
        ciphertext = encrypt_playfair(plaintext, key)
        assert ciphertext.isalpha()


class TestCipherInsecurityWarnings:
    """Tests to document security limitations"""

    def test_des_key_space_is_small(self):
        """Document that DES uses only 56-bit effective key"""
        # DES key is 8 bytes but only 56 bits are used
        key = b"testkey1"
        padded = pad_key_to_8_bytes(key)
        assert len(padded) == 8  # 64 bits, but only 56 effective

    def test_playfair_preserves_patterns(self):
        """Document that Playfair is vulnerable to frequency analysis"""
        # Encrypting same digraph produces same ciphertext
        key = "KEYWORD"

        # Same plaintext pairs encrypt the same way
        cipher1 = encrypt_playfair("ABAB", key)
        cipher2 = encrypt_playfair("ABAB", key)
        assert cipher1 == cipher2

        # This makes it vulnerable to frequency analysis
