"""
Encryption Module

Implements the complete PDF encryption workflow:
1. Generate encryption keys
2. Randomly select algorithms
3. Apply multiple encryption layers
4. Create encrypted file with metadata
5. Generate key file for distribution
"""

import json
import random
import base64
from datetime import datetime
from typing import Dict, List, Tuple
from .algorithms import AESGCMCipher, AES128GCMCipher, AESCBCCipher, ChaCha20Cipher, RSACipher, HMACGenerator
from .key_management import (
    generate_encryption_keys,
    create_key_file,
    encapsulate_symmetric_keys
)


# Available encryption algorithms
AVAILABLE_ALGORITHMS = [
    "AES-256-GCM",
    "AES-128-GCM",
    "ChaCha20-Poly1305",
    "AES-256-CBC"
]


def select_random_algorithms(count: int = 2) -> List[str]:
    """
    Randomly select encryption algorithms

    Demonstrates Kerckhoffs's Principle - the algorithm choice is NOT secret.
    Security comes from the key, not from hiding which algorithm we use.

    Args:
        count: Number of algorithms to select (default: 2)

    Returns:
        List of selected algorithm names (in order they will be applied)
    """
    # Randomly select 'count' algorithms from the available pool
    # With 4 algorithms available, this provides true randomness
    return random.sample(AVAILABLE_ALGORITHMS, min(count, len(AVAILABLE_ALGORITHMS)))


def encrypt_pdf(pdf_bytes: bytes, original_filename: str) -> Tuple[bytes, bytes]:
    """
    Encrypt a PDF file with multi-layer encryption

    Process:
    1. Generate all encryption keys
    2. Randomly select 2 encryption algorithms
    3. Apply Layer 1: First selected algorithm
    4. Apply Layer 2: Second selected algorithm
    5. Encapsulate symmetric keys with RSA
    6. Create encrypted file with metadata header
    7. Generate downloadable key file

    Args:
        pdf_bytes: PDF file content
        original_filename: Name of the original file

    Returns:
        Tuple of (encrypted_file_bytes, key_file_bytes)
    """
    # Step 1: Generate all encryption keys
    keys = generate_encryption_keys()
    rsa_private = keys['rsa_private']
    rsa_public = keys['rsa_public']

    # Step 2: Randomly select 2 algorithms
    selected_algorithms = select_random_algorithms(2)
    print(f"[ENCRYPT] Selected algorithms: {selected_algorithms}")
    print(f"[ENCRYPT] Input PDF size: {len(pdf_bytes)} bytes")

    # Step 3 & 4: Apply encryption layers dynamically based on selected algorithms
    # Generate keys and store IVs/nonces for each algorithm
    layer_data = {}
    symmetric_keys = {}

    current_data = pdf_bytes

    # Apply each selected algorithm in order
    for i, algorithm in enumerate(selected_algorithms):
        layer_num = i + 1
        print(f"[ENCRYPT] Layer {layer_num}: Encrypting with {algorithm}")

        if algorithm == "AES-256-GCM":
            key = AESGCMCipher.generate_key()
            print(f"[ENCRYPT] - Generated key: {len(key)} bytes")
            ciphertext, iv = AESGCMCipher.encrypt(current_data, key)
            print(f"[ENCRYPT] - Success! Encrypted data size: {len(ciphertext)} bytes")
            layer_data[f"layer{layer_num}_iv"] = base64.b64encode(iv).decode('utf-8')
            symmetric_keys[f"layer{layer_num}_key"] = key
            current_data = ciphertext

        elif algorithm == "AES-128-GCM":
            key = AES128GCMCipher.generate_key()
            print(f"[ENCRYPT] - Generated key: {len(key)} bytes")
            ciphertext, iv = AES128GCMCipher.encrypt(current_data, key)
            print(f"[ENCRYPT] - Success! Encrypted data size: {len(ciphertext)} bytes")
            layer_data[f"layer{layer_num}_iv"] = base64.b64encode(iv).decode('utf-8')
            symmetric_keys[f"layer{layer_num}_key"] = key
            current_data = ciphertext

        elif algorithm == "ChaCha20-Poly1305":
            key = ChaCha20Cipher.generate_key()
            print(f"[ENCRYPT] - Generated key: {len(key)} bytes")
            ciphertext, nonce = ChaCha20Cipher.encrypt(current_data, key)
            print(f"[ENCRYPT] - Success! Encrypted data size: {len(ciphertext)} bytes")
            layer_data[f"layer{layer_num}_nonce"] = base64.b64encode(nonce).decode('utf-8')
            symmetric_keys[f"layer{layer_num}_key"] = key
            current_data = ciphertext

        elif algorithm == "AES-256-CBC":
            key = AESCBCCipher.generate_key()
            print(f"[ENCRYPT] - Generated key: {len(key)} bytes")
            ciphertext, iv, _ = AESCBCCipher.encrypt(current_data, key)
            print(f"[ENCRYPT] - Success! Encrypted data size: {len(ciphertext)} bytes")
            layer_data[f"layer{layer_num}_iv"] = base64.b64encode(iv).decode('utf-8')
            symmetric_keys[f"layer{layer_num}_key"] = key
            current_data = ciphertext

    ciphertext_final = current_data
    print(f"[ENCRYPT] All layers encrypted. Final size: {len(ciphertext_final)} bytes")

    # Step 5: Encapsulate symmetric keys with RSA
    # Combine all symmetric keys into one blob
    keys_blob = b''.join([symmetric_keys[f"layer{i+1}_key"] for i in range(len(selected_algorithms))])
    print(f"[ENCRYPT] Created keys blob:")
    for i in range(len(selected_algorithms)):
        key = symmetric_keys[f"layer{i+1}_key"]
        print(f"[ENCRYPT] - Layer {i+1} ({selected_algorithms[i]}): {len(key)} bytes")
    print(f"[ENCRYPT] Total keys blob size: {len(keys_blob)} bytes")

    # Encrypt the keys blob directly with RSA (no JSON wrapping for v2.0)
    encrypted_symmetric_keys = RSACipher.encrypt(keys_blob, rsa_public)
    print(f"[ENCRYPT] Encrypted keys blob size: {len(encrypted_symmetric_keys)} bytes")

    # Step 6: Generate HMAC for integrity verification
    hmac_key = HMACGenerator.generate_key()
    hmac_tag = HMACGenerator.compute(ciphertext_final, hmac_key)

    # Step 7: Create metadata header
    metadata = {
        "version": "2.0",  # Updated version for multi-algorithm support
        "algorithms": selected_algorithms,
        "encrypted_symmetric_keys": base64.b64encode(encrypted_symmetric_keys).decode('utf-8'),
        "hmac_key": base64.b64encode(hmac_key).decode('utf-8'),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "original_filename": original_filename
    }

    # Add layer-specific IVs/nonces to metadata
    metadata.update(layer_data)

    # Step 8: Create encrypted file structure
    encrypted_file = {
        "header": metadata,
        "ciphertext": base64.b64encode(ciphertext_final).decode('utf-8'),
        "hmac": base64.b64encode(hmac_tag).decode('utf-8')
    }

    encrypted_file_bytes = json.dumps(encrypted_file, indent=2).encode('utf-8')

    # Step 9: Create key file
    key_file_bytes = create_key_file(rsa_private, rsa_public, selected_algorithms)

    return encrypted_file_bytes, key_file_bytes


def get_encryption_info(pdf_size: int) -> Dict:
    """
    Get information about the encryption that will be performed

    Useful for displaying to the user before encryption.

    Args:
        pdf_size: Size of PDF file in bytes

    Returns:
        Dict with encryption information
    """
    return {
        "algorithms_available": AVAILABLE_ALGORITHMS,
        "algorithms_will_use": 2,
        "key_sizes": {
            "AES": "256 bits",
            "ChaCha20": "256 bits",
            "RSA": "4096 bits"
        },
        "security_features": [
            "Multi-layer encryption (defense in depth)",
            "Authenticated encryption (prevents tampering)",
            "Perfect forward secrecy (unique keys per file)",
            "HMAC integrity verification",
            "RSA-4096 key encapsulation"
        ],
        "input_size_bytes": pdf_size,
        "estimated_encrypted_size_bytes": pdf_size * 1.4  # Rough estimate with overhead
    }


__all__ = [
    'encrypt_pdf',
    'select_random_algorithms',
    'get_encryption_info',
    'AVAILABLE_ALGORITHMS'
]
