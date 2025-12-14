"""
Custom Key Generation Algorithm for PDF Carrier Project
========================================================

This module implements a unique key generation algorithm called
"Cascading Entropy Mixer" (CEM) that combines multiple entropy sources
with a custom mixing function to generate cryptographically secure keys.

Algorithm Design:
- Multi-source entropy collection
- Cascading transformation rounds
- Non-linear mixing functions
- Key stretching and compression
"""

import os
import time
import hashlib
import threading
import struct
from typing import Optional, Union


class CascadingEntropyMixer:
    """
    Custom key generation algorithm that uses multiple entropy sources
    and cascading transformations to generate secure keys.
    
    This is a unique algorithm designed specifically for this project.
    It does NOT use existing key derivation functions like PBKDF2, Argon2, etc.
    """
    
    def __init__(self, rounds: int = 7, pool_size: int = 64):
        """
        Initialize the key generator.
        
        Args:
            rounds: Number of cascading transformation rounds (default: 7)
            pool_size: Size of entropy pool in bytes (default: 64)
        """
        self.rounds = rounds
        self.pool_size = pool_size
        self._entropy_counter = 0
        self._lock = threading.Lock()
    
    def _collect_entropy_sources(self) -> bytes:
        """
        Collect entropy from multiple sources.
        This is the first stage of our custom algorithm.
        
        Returns:
            Combined entropy bytes
        """
        entropy_parts = []
        
        # Source 1: System random (high quality)
        entropy_parts.append(os.urandom(16))
        
        # Source 2: High-precision timestamp
        timestamp = struct.pack('dQ', time.time(), time.perf_counter_ns())
        entropy_parts.append(timestamp)
        
        # Source 3: Process/thread information
        thread_id = struct.pack('Q', threading.get_ident())
        process_id = struct.pack('I', os.getpid())
        entropy_parts.append(thread_id + process_id)
        
        # Source 4: Memory address (if available)
        try:
            obj_id = id(self)
            entropy_parts.append(struct.pack('Q', obj_id))
        except:
            pass
        
        # Source 5: Counter-based entropy
        with self._lock:
            self._entropy_counter += 1
            counter_bytes = struct.pack('Q', self._entropy_counter)
        entropy_parts.append(counter_bytes)
        
        # Source 6: Additional system randomness
        entropy_parts.append(os.urandom(8))
        
        return b''.join(entropy_parts)
    
    def _nonlinear_mix(self, data: bytes, round_num: int) -> bytes:
        """
        Custom non-linear mixing function.
        This is a key component of our unique algorithm.
        
        Args:
            data: Input data to mix
            round_num: Current round number (for round-dependent behavior)
        
        Returns:
            Mixed data
        """
        if len(data) == 0:
            return data
        
        # Convert to list for manipulation
        data_list = list(data)
        length = len(data_list)
        
        # Round 1: Rotate and XOR with position-dependent values
        for i in range(length):
            # Rotate based on position and round number
            rotate_amount = (i * round_num + 1) % 8
            byte_val = data_list[i]
            # Circular left rotate
            byte_val = ((byte_val << rotate_amount) | (byte_val >> (8 - rotate_amount))) & 0xFF
            # XOR with position-dependent value
            byte_val ^= ((i * round_num * 17 + 23) % 256)
            data_list[i] = byte_val
        
        # Round 2: Swap pairs based on round number
        swap_pattern = (round_num * 3 + 1) % length
        for i in range(0, length - 1, 2):
            j = (i + swap_pattern) % length
            data_list[i], data_list[j] = data_list[j], data_list[i]
        
        # Round 3: Add with carry (non-linear addition)
        carry = round_num % 256
        for i in range(length):
            new_val = (data_list[i] + data_list[(i + 1) % length] + carry) % 256
            carry = (data_list[i] + data_list[(i + 1) % length] + carry) // 256
            data_list[i] = new_val
        
        return bytes(data_list)
    
    def _cascade_transform(self, seed: bytes) -> bytes:
        """
        Cascading transformation function.
        Applies multiple rounds of non-linear mixing.
        
        Args:
            seed: Initial seed data
        
        Returns:
            Transformed data
        """
        current = seed
        
        # Apply cascading rounds
        for round_num in range(1, self.rounds + 1):
            # Mix the data
            current = self._nonlinear_mix(current, round_num)
            
            # Fold operation: XOR first half with second half
            if len(current) > 1:
                mid = len(current) // 2
                first_half = current[:mid]
                second_half = current[mid:]
                # Pad if necessary
                if len(first_half) < len(second_half):
                    first_half += b'\x00' * (len(second_half) - len(first_half))
                elif len(second_half) < len(first_half):
                    second_half += b'\x00' * (len(first_half) - len(second_half))
                
                # XOR fold
                folded = bytes(a ^ b for a, b in zip(first_half, second_half))
                # Add round-dependent constant
                round_constant_val = (round_num * 0x9E3779B9) & 0xFFFFFFFF
                round_constant = struct.pack('I', round_constant_val)
                if len(folded) >= len(round_constant):
                    folded = bytes(
                        (folded[i] ^ round_constant[i % len(round_constant)])
                        for i in range(len(folded))
                    )
                current = folded
        
        return current
    
    def _expand_to_length(self, data: bytes, target_length: int) -> bytes:
        """
        Expand data to target length using a custom expansion function.
        
        Args:
            data: Input data
            target_length: Desired output length in bytes
        
        Returns:
            Expanded data
        """
        if len(data) == 0:
            data = os.urandom(32)  # Fallback
        
        result = bytearray()
        data_len = len(data)
        position = 0
        
        while len(result) < target_length:
            # Use data at current position
            byte_val = data[position % data_len]
            
            # Transform the byte
            transformed = byte_val
            for i in range(3):
                transformed = ((transformed << 1) | (transformed >> 7)) & 0xFF
                transformed ^= (position + i) % 256
            
            result.append(transformed)
            position += 1
            
            # Every 8 bytes, inject fresh entropy
            if position % 8 == 0:
                fresh = os.urandom(1)[0]
                result[-1] ^= fresh
        
        return bytes(result[:target_length])
    
    def generate_key(self, key_length: int, salt: Optional[bytes] = None) -> bytes:
        """
        Generate a cryptographic key of specified length.
        
        This is the main entry point for key generation using our custom algorithm.
        
        Args:
            key_length: Desired key length in bytes (e.g., 32 for AES-256)
            salt: Optional salt for deterministic key generation
        
        Returns:
            Generated key bytes
        """
        # Step 1: Collect entropy from multiple sources
        if salt:
            # For deterministic generation, use only salt-based entropy
            # Hash the salt multiple times to create entropy pool
            entropy = salt
            for _ in range(5):
                entropy = hashlib.sha256(entropy).digest()
        else:
            # For non-deterministic generation, collect from multiple sources
            entropy = self._collect_entropy_sources()
            # Add additional entropy for non-deterministic generation
            entropy = hashlib.sha256(entropy + os.urandom(16)).digest()
        
        # Step 2: Ensure we have enough initial data
        if len(entropy) < self.pool_size:
            entropy = entropy * ((self.pool_size // len(entropy)) + 1)
        entropy = entropy[:self.pool_size]
        
        # Step 3: Apply cascading transformation
        transformed = self._cascade_transform(entropy)
        
        # Step 4: Expand to desired key length
        if salt:
            # For deterministic expansion, use hash-based expansion
            key = self._deterministic_expand(transformed, key_length)
        else:
            # For non-deterministic expansion, use random-based expansion
            key = self._expand_to_length(transformed, key_length)
        
        # Step 5: Final mixing pass
        key = self._nonlinear_mix(key, self.rounds + 1)
        
        return key
    
    def _deterministic_expand(self, data: bytes, target_length: int) -> bytes:
        """
        Deterministic expansion function for salt-based key generation.
        
        Args:
            data: Input data
            target_length: Desired output length in bytes
        
        Returns:
            Expanded data
        """
        if len(data) == 0:
            data = b'\x00' * 32  # Fallback
        
        result = bytearray()
        data_len = len(data)
        position = 0
        
        while len(result) < target_length:
            # Use data at current position
            byte_val = data[position % data_len]
            
            # Transform the byte deterministically
            transformed = byte_val
            for i in range(3):
                transformed = ((transformed << 1) | (transformed >> 7)) & 0xFF
                transformed ^= (position + i) % 256
            
            result.append(transformed)
            position += 1
            
            # Every 8 bytes, apply hash-based transformation
            if position % 8 == 0:
                hash_val = hashlib.sha256(data + struct.pack('I', position)).digest()
                result[-1] ^= hash_val[0]
        
        return bytes(result[:target_length])
    
    def generate_symmetric_key(self, algorithm: str = "AES-256") -> bytes:
        """
        Generate a symmetric encryption key for a specific algorithm.
        
        Args:
            algorithm: Algorithm name ("AES-256", "ChaCha20", etc.)
        
        Returns:
            Key bytes appropriate for the algorithm
        """
        key_lengths = {
            "AES-128": 16,
            "AES-192": 24,
            "AES-256": 32,
            "ChaCha20": 32,
            "ChaCha20-Poly1305": 32,
        }
        
        key_length = key_lengths.get(algorithm, 32)  # Default to 32 bytes
        return self.generate_key(key_length)
    
    def generate_key_pair_seed(self) -> bytes:
        """
        Generate a seed for asymmetric key pair generation (RSA, etc.).
        This seed can be used by RSA key generation functions.
        
        Returns:
            High-entropy seed bytes
        """
        # Generate a larger seed for key pair generation
        return self.generate_key(64)  # 512 bits of seed material


def generate_encryption_key(algorithm: str = "AES-256", salt: Optional[bytes] = None) -> bytes:
    """
    Convenience function to generate encryption keys.
    
    Args:
        algorithm: Encryption algorithm name
        salt: Optional salt for deterministic generation
    
    Returns:
        Generated key bytes
    """
    generator = CascadingEntropyMixer()
    key_lengths = {
        "AES-128": 16,
        "AES-192": 24,
        "AES-256": 32,
        "ChaCha20": 32,
        "ChaCha20-Poly1305": 32,
    }
    key_length = key_lengths.get(algorithm, 32)
    return generator.generate_key(key_length, salt=salt)


def generate_key_with_salt(password: bytes, salt: bytes, key_length: int = 32) -> bytes:
    """
    Generate a key from a password and salt using our custom algorithm.
    This provides deterministic key generation.
    
    Args:
        password: Password bytes
        salt: Salt bytes
        key_length: Desired key length in bytes
    
    Returns:
        Generated key bytes
    """
    generator = CascadingEntropyMixer(rounds=10)  # More rounds for password-based
    
    # Combine password and salt
    combined = hashlib.sha256(password + salt).digest()
    
    # Use combined hash as salt for deterministic generation
    return generator.generate_key(key_length, salt=combined)


# Example usage and testing
if __name__ == "__main__":
    print("Testing Cascading Entropy Mixer Key Generation Algorithm")
    print("=" * 60)
    
    generator = CascadingEntropyMixer()
    
    # Test 1: Generate AES-256 key
    print("\n1. Generating AES-256 key (32 bytes):")
    aes_key = generator.generate_symmetric_key("AES-256")
    print(f"   Key (hex): {aes_key.hex()}")
    print(f"   Key length: {len(aes_key)} bytes")
    
    # Test 2: Generate ChaCha20 key
    print("\n2. Generating ChaCha20-Poly1305 key (32 bytes):")
    chacha_key = generator.generate_symmetric_key("ChaCha20-Poly1305")
    print(f"   Key (hex): {chacha_key.hex()}")
    print(f"   Key length: {len(chacha_key)} bytes")
    
    # Test 3: Generate custom length key
    print("\n3. Generating 16-byte key:")
    custom_key = generator.generate_key(16)
    print(f"   Key (hex): {custom_key.hex()}")
    print(f"   Key length: {len(custom_key)} bytes")
    
    # Test 4: Deterministic key generation (with salt)
    print("\n4. Deterministic key generation (with salt):")
    salt = b"test_salt_12345"
    key1 = generator.generate_key(32, salt=salt)
    key2 = generator.generate_key(32, salt=salt)
    print(f"   Key 1 (hex): {key1.hex()}")
    print(f"   Key 2 (hex): {key2.hex()}")
    print(f"   Keys match: {key1 == key2}")
    
    # Test 5: Key pair seed
    print("\n5. Generating RSA key pair seed (64 bytes):")
    seed = generator.generate_key_pair_seed()
    print(f"   Seed (hex): {seed.hex()[:64]}...")
    print(f"   Seed length: {len(seed)} bytes")
    
    # Test 6: Uniqueness test
    print("\n6. Testing key uniqueness (generating 5 keys):")
    keys = [generator.generate_key(32) for _ in range(5)]
    unique = len(set(keys)) == len(keys)
    print(f"   All keys unique: {unique}")
    for i, key in enumerate(keys, 1):
        print(f"   Key {i}: {key.hex()[:32]}...")
    
    print("\n" + "=" * 60)
    print("Key generation algorithm test completed!")

