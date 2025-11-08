"""
Decryption Module

Implements the complete PDF decryption workflow:
1. Parse encrypted file metadata
2. Load and verify key file
3. Verify file integrity (HMAC)
4. Decrypt symmetric keys with RSA
5. Remove encryption layers in reverse order
6. Return original PDF
"""

import json
import base64
from typing import Dict, Tuple
from .algorithms import AESGCMCipher, AES128GCMCipher, AESCBCCipher, ChaCha20Cipher, HMACGenerator
from .key_management import load_key_file, decapsulate_symmetric_keys


def decrypt_pdf(encrypted_file_bytes: bytes, key_file_bytes: bytes) -> Tuple[bytes, Dict]:
    """
    Decrypt an encrypted PDF file

    Process:
    1. Parse encrypted file metadata header
    2. Load RSA private key from key file
    3. Verify HMAC (integrity check)
    4. Decrypt symmetric keys using RSA
    5. Remove encryption layers in reverse order (dynamically based on algorithms used)
    6. Return original PDF

    Args:
        encrypted_file_bytes: Encrypted file content
        key_file_bytes: Key file content

    Returns:
        Tuple of (decrypted_pdf_bytes, metadata_dict)

    Raises:
        ValueError: If file format is invalid or integrity check fails
        Exception: If decryption fails (wrong key, corrupted data, etc.)
    """
    # Step 1: Parse encrypted file
    try:
        encrypted_file = json.loads(encrypted_file_bytes.decode('utf-8'))
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid encrypted file format: {e}")

    # Validate file structure
    if 'header' not in encrypted_file or 'ciphertext' not in encrypted_file:
        raise ValueError("Missing required fields in encrypted file")

    header = encrypted_file['header']
    ciphertext = base64.b64decode(encrypted_file['ciphertext'])
    expected_hmac = base64.b64decode(encrypted_file.get('hmac', ''))

    # Step 2: Load key file
    try:
        key_data = load_key_file(key_file_bytes)
        private_key = key_data['private_key']
    except ValueError as e:
        raise ValueError(f"Invalid key file: {e}")

    # Step 3: Verify HMAC (integrity check)
    try:
        hmac_key = base64.b64decode(header['hmac_key'])
        if not HMACGenerator.verify(ciphertext, hmac_key, expected_hmac):
            raise ValueError("HMAC verification failed - file may have been tampered with")
    except KeyError:
        raise ValueError("Missing HMAC data in encrypted file")

    # Step 4: Extract encryption parameters from header
    try:
        encrypted_symmetric_keys = base64.b64decode(header['encrypted_symmetric_keys'])
        algorithms = header['algorithms']
        original_filename = header.get('original_filename', 'decrypted.pdf')
        version = header.get('version', '1.0')
    except KeyError as e:
        raise ValueError(f"Missing required header field: {e}")

    # Step 5: Decrypt symmetric keys using RSA private key
    try:
        # For version 2.0+, we have a blob of keys
        if version == "2.0":
            from .algorithms import RSACipher
            decrypted_keys_blob = RSACipher.decrypt(encrypted_symmetric_keys, private_key)
            print(f"[DECRYPT] Decrypted keys blob size: {len(decrypted_keys_blob)} bytes")

            # Split the blob into individual keys based on algorithms
            symmetric_keys = {}
            offset = 0
            for i, algorithm in enumerate(algorithms):
                layer_num = i + 1
                # Determine key size based on algorithm
                if algorithm == "AES-128-GCM":
                    key_size = 16
                else:  # AES-256-GCM, ChaCha20, AES-256-CBC
                    key_size = 32

                symmetric_keys[f"layer{layer_num}_key"] = decrypted_keys_blob[offset:offset + key_size]
                print(f"[DECRYPT] Extracted layer{layer_num}_key for {algorithm}: offset={offset}, size={key_size} bytes")
                offset += key_size
        else:
            # Legacy version 1.0 support
            aes_key, chacha_key = decapsulate_symmetric_keys(encrypted_symmetric_keys, private_key)
    except Exception as e:
        raise ValueError(f"Failed to decrypt symmetric keys - wrong key file? {e}")

    # Step 6: Remove encryption layers in reverse order
    try:
        current_data = ciphertext
        print(f"[DECRYPT] Starting decryption with {len(algorithms)} layers")
        print(f"[DECRYPT] Algorithms to decrypt (in reverse): {list(reversed(algorithms))}")
        print(f"[DECRYPT] Version: {version}")

        # Apply decryption in REVERSE order (last layer first)
        for i in reversed(range(len(algorithms))):
            algorithm = algorithms[i]
            layer_num = i + 1
            print(f"[DECRYPT] Layer {layer_num}: Decrypting with {algorithm}")

            if algorithm == "AES-256-GCM":
                key = symmetric_keys[f"layer{layer_num}_key"]
                iv = base64.b64decode(header[f"layer{layer_num}_iv"])
                print(f"[DECRYPT] - Key length: {len(key)} bytes, IV length: {len(iv)} bytes")
                current_data = AESGCMCipher.decrypt(current_data, key, iv)
                print(f"[DECRYPT] - Success! Decrypted data size: {len(current_data)} bytes")

            elif algorithm == "AES-128-GCM":
                key = symmetric_keys[f"layer{layer_num}_key"]
                iv = base64.b64decode(header[f"layer{layer_num}_iv"])
                print(f"[DECRYPT] - Key length: {len(key)} bytes, IV length: {len(iv)} bytes")
                current_data = AES128GCMCipher.decrypt(current_data, key, iv)
                print(f"[DECRYPT] - Success! Decrypted data size: {len(current_data)} bytes")

            elif algorithm == "ChaCha20-Poly1305":
                key = symmetric_keys[f"layer{layer_num}_key"]
                nonce = base64.b64decode(header[f"layer{layer_num}_nonce"])
                print(f"[DECRYPT] - Key length: {len(key)} bytes, Nonce length: {len(nonce)} bytes")
                current_data = ChaCha20Cipher.decrypt(current_data, key, nonce)
                print(f"[DECRYPT] - Success! Decrypted data size: {len(current_data)} bytes")

            elif algorithm == "AES-256-CBC":
                key = symmetric_keys[f"layer{layer_num}_key"]
                iv = base64.b64decode(header[f"layer{layer_num}_iv"])
                print(f"[DECRYPT] - Key length: {len(key)} bytes, IV length: {len(iv)} bytes")
                current_data = AESCBCCipher.decrypt(current_data, key, iv)
                print(f"[DECRYPT] - Success! Decrypted data size: {len(current_data)} bytes")

        pdf_bytes = current_data
        print(f"[DECRYPT] All layers decrypted successfully! Final PDF size: {len(pdf_bytes)} bytes")

    except Exception as e:
        import traceback
        print(f"[DECRYPT ERROR] Failed at layer {layer_num} ({algorithm})")
        print(f"[DECRYPT ERROR] Exception: {type(e).__name__}: {e}")
        print(f"[DECRYPT ERROR] Traceback:\n{traceback.format_exc()}")
        raise ValueError(f"Decryption failed at layer {layer_num} ({algorithm}): {type(e).__name__}: {str(e)}")

    # Step 7: Prepare metadata for response
    metadata = {
        "original_filename": original_filename,
        "algorithms_used": algorithms,
        "timestamp": header.get('timestamp'),
        "version": version,
        "verified": True,  # HMAC passed
        "integrity_check": "PASSED"
    }

    return pdf_bytes, metadata


def parse_encrypted_file_metadata(encrypted_file_bytes: bytes) -> Dict:
    """
    Parse metadata from an encrypted file without decrypting

    Useful for displaying information to the user before decryption.

    Args:
        encrypted_file_bytes: Encrypted file content

    Returns:
        Dict with metadata information

    Raises:
        ValueError: If file format is invalid
    """
    try:
        encrypted_file = json.loads(encrypted_file_bytes.decode('utf-8'))
        header = encrypted_file['header']

        return {
            "version": header.get('version'),
            "algorithms": header.get('algorithms', []),
            "timestamp": header.get('timestamp'),
            "original_filename": header.get('original_filename'),
            "file_size_bytes": len(encrypted_file_bytes)
        }

    except (json.JSONDecodeError, KeyError) as e:
        raise ValueError(f"Invalid encrypted file: {e}")


__all__ = [
    'decrypt_pdf',
    'parse_encrypted_file_metadata'
]
