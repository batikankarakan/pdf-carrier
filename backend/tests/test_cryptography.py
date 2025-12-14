"""
Unit tests for CascadingEntropyMixer (CEM) key generation algorithm
"""

import pytest
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.cryptography import (
    CascadingEntropyMixer,
    generate_encryption_key,
    generate_key_with_salt
)


class TestCascadingEntropyMixer:
    """Tests for the CascadingEntropyMixer class"""

    def test_initialization(self):
        """Test CEM initializes with correct parameters"""
        cem = CascadingEntropyMixer(rounds=7, pool_size=64)
        assert cem.rounds == 7
        assert cem.pool_size == 64

    def test_custom_initialization(self):
        """Test CEM with custom parameters"""
        cem = CascadingEntropyMixer(rounds=10, pool_size=128)
        assert cem.rounds == 10
        assert cem.pool_size == 128

    def test_generate_key_correct_length(self):
        """Test that generated keys have correct length"""
        cem = CascadingEntropyMixer()

        # Test various key lengths
        key_lengths = [8, 16, 24, 32, 64, 128]
        for length in key_lengths:
            key = cem.generate_key(length)
            assert len(key) == length, f"Expected {length} bytes, got {len(key)}"

    def test_generate_key_uniqueness(self):
        """Test that generated keys are unique"""
        cem = CascadingEntropyMixer()

        # Generate 100 keys and check uniqueness
        keys = [cem.generate_key(32) for _ in range(100)]
        unique_keys = set(keys)
        assert len(unique_keys) == 100, "Generated keys should be unique"

    def test_generate_key_randomness(self):
        """Test that keys have good randomness distribution"""
        cem = CascadingEntropyMixer()
        key = cem.generate_key(1000)

        # Check byte distribution (should be roughly uniform)
        byte_counts = [0] * 256
        for byte in key:
            byte_counts[byte] += 1

        # No single byte value should dominate (>5% of total)
        max_count = max(byte_counts)
        assert max_count < 50, f"Poor randomness: one byte appears {max_count} times"

    def test_generate_key_with_salt_deterministic(self):
        """Test that same salt produces same key"""
        cem = CascadingEntropyMixer()
        salt = b"test_salt_12345"

        key1 = cem.generate_key(32, salt=salt)
        key2 = cem.generate_key(32, salt=salt)

        assert key1 == key2, "Same salt should produce same key"

    def test_generate_key_different_salts(self):
        """Test that different salts produce different keys"""
        cem = CascadingEntropyMixer()

        key1 = cem.generate_key(32, salt=b"salt_one")
        key2 = cem.generate_key(32, salt=b"salt_two")

        assert key1 != key2, "Different salts should produce different keys"

    def test_generate_symmetric_key_aes256(self):
        """Test AES-256 key generation"""
        cem = CascadingEntropyMixer()
        key = cem.generate_symmetric_key("AES-256")
        assert len(key) == 32, "AES-256 key should be 32 bytes"

    def test_generate_symmetric_key_aes128(self):
        """Test AES-128 key generation"""
        cem = CascadingEntropyMixer()
        key = cem.generate_symmetric_key("AES-128")
        assert len(key) == 16, "AES-128 key should be 16 bytes"

    def test_generate_symmetric_key_chacha20(self):
        """Test ChaCha20 key generation"""
        cem = CascadingEntropyMixer()
        key = cem.generate_symmetric_key("ChaCha20-Poly1305")
        assert len(key) == 32, "ChaCha20 key should be 32 bytes"

    def test_generate_key_pair_seed(self):
        """Test RSA key pair seed generation"""
        cem = CascadingEntropyMixer()
        seed = cem.generate_key_pair_seed()
        assert len(seed) == 64, "Key pair seed should be 64 bytes"

    def test_entropy_counter_increments(self):
        """Test that entropy counter increments with each call"""
        cem = CascadingEntropyMixer()
        initial_counter = cem._entropy_counter

        cem.generate_key(32)
        assert cem._entropy_counter > initial_counter

    def test_thread_safety(self):
        """Test that CEM is thread-safe"""
        import threading

        cem = CascadingEntropyMixer()
        keys = []
        errors = []

        def generate_keys():
            try:
                for _ in range(10):
                    key = cem.generate_key(32)
                    keys.append(key)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=generate_keys) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0, f"Thread errors: {errors}"
        assert len(keys) == 100, "Should generate 100 keys"
        assert len(set(keys)) == 100, "All keys should be unique"


class TestConvenienceFunctions:
    """Tests for convenience functions"""

    def test_generate_encryption_key_default(self):
        """Test default encryption key generation"""
        key = generate_encryption_key()
        assert len(key) == 32, "Default key should be 32 bytes"

    def test_generate_encryption_key_aes128(self):
        """Test AES-128 encryption key generation"""
        key = generate_encryption_key("AES-128")
        assert len(key) == 16

    def test_generate_encryption_key_with_salt(self):
        """Test encryption key generation with salt"""
        salt = b"my_salt"
        key1 = generate_encryption_key("AES-256", salt=salt)
        key2 = generate_encryption_key("AES-256", salt=salt)
        assert key1 == key2

    def test_generate_key_with_salt_function(self):
        """Test generate_key_with_salt function"""
        password = b"my_password"
        salt = b"my_salt"

        key1 = generate_key_with_salt(password, salt, 32)
        key2 = generate_key_with_salt(password, salt, 32)

        assert key1 == key2, "Same password+salt should produce same key"
        assert len(key1) == 32

    def test_generate_key_with_salt_different_passwords(self):
        """Test that different passwords produce different keys"""
        salt = b"same_salt"

        key1 = generate_key_with_salt(b"password1", salt, 32)
        key2 = generate_key_with_salt(b"password2", salt, 32)

        assert key1 != key2


class TestNonLinearMixing:
    """Tests for the non-linear mixing function"""

    def test_nonlinear_mix_changes_data(self):
        """Test that mixing changes the input data"""
        cem = CascadingEntropyMixer()
        data = bytes(range(64))

        mixed = cem._nonlinear_mix(data, 1)
        assert mixed != data, "Mixed data should differ from input"

    def test_nonlinear_mix_deterministic(self):
        """Test that mixing is deterministic for same round"""
        cem = CascadingEntropyMixer()
        data = bytes(range(64))

        mixed1 = cem._nonlinear_mix(data, 1)
        mixed2 = cem._nonlinear_mix(data, 1)

        assert mixed1 == mixed2, "Same input and round should produce same output"

    def test_nonlinear_mix_different_rounds(self):
        """Test that different rounds produce different results"""
        cem = CascadingEntropyMixer()
        data = bytes(range(64))

        mixed1 = cem._nonlinear_mix(data, 1)
        mixed2 = cem._nonlinear_mix(data, 2)

        assert mixed1 != mixed2, "Different rounds should produce different output"

    def test_nonlinear_mix_empty_data(self):
        """Test mixing with empty data"""
        cem = CascadingEntropyMixer()
        result = cem._nonlinear_mix(b"", 1)
        assert result == b"", "Empty input should return empty output"


class TestCascadeTransform:
    """Tests for the cascade transformation"""

    def test_cascade_transform_reduces_data(self):
        """Test that cascade transform reduces data size (folding)"""
        cem = CascadingEntropyMixer()
        seed = bytes(range(64))

        result = cem._cascade_transform(seed)
        # After folding operations, size should be reduced
        assert len(result) < len(seed)

    def test_cascade_transform_deterministic(self):
        """Test that cascade transform is deterministic"""
        cem = CascadingEntropyMixer()
        seed = bytes(range(64))

        result1 = cem._cascade_transform(seed)
        result2 = cem._cascade_transform(seed)

        assert result1 == result2


class TestKeyExpansion:
    """Tests for key expansion functions"""

    def test_expand_to_length(self):
        """Test key expansion to target length"""
        cem = CascadingEntropyMixer()
        data = bytes(range(32))

        expanded = cem._expand_to_length(data, 64)
        assert len(expanded) == 64

    def test_expand_to_shorter_length(self):
        """Test expansion to shorter length (truncation)"""
        cem = CascadingEntropyMixer()
        data = bytes(range(64))

        result = cem._expand_to_length(data, 32)
        assert len(result) == 32

    def test_deterministic_expand(self):
        """Test deterministic expansion for salt-based keys"""
        cem = CascadingEntropyMixer()
        data = bytes(range(32))

        result1 = cem._deterministic_expand(data, 64)
        result2 = cem._deterministic_expand(data, 64)

        assert result1 == result2
        assert len(result1) == 64


class TestEdgeCases:
    """Tests for edge cases and error conditions"""

    def test_generate_key_length_zero(self):
        """Test generating zero-length key"""
        cem = CascadingEntropyMixer()
        key = cem.generate_key(0)
        assert len(key) == 0

    def test_generate_very_long_key(self):
        """Test generating very long key"""
        cem = CascadingEntropyMixer()
        key = cem.generate_key(1024)
        assert len(key) == 1024

    def test_rapid_key_generation(self):
        """Test rapid consecutive key generation"""
        cem = CascadingEntropyMixer()

        # Generate 1000 keys rapidly
        keys = [cem.generate_key(32) for _ in range(1000)]

        # All should be unique
        assert len(set(keys)) == 1000
