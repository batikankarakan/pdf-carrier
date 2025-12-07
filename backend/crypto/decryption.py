"""
Decryption Module

Implements the complete PDF decryption workflow:
1. Extract encrypted text from PDF
2. Load and verify key file
3. Verify file integrity (HMAC)
4. Decrypt symmetric keys with RSA
5. Remove encryption layers in reverse order from text
6. Create PDF with decrypted text
7. Return decrypted PDF
"""

import json
import base64
from typing import Dict, Tuple
from .algorithms import AESGCMCipher, AES128GCMCipher, AESCBCCipher, ChaCha20Cipher, DESCipher, HMACGenerator, RSACipher
from .key_management import load_key_file, decapsulate_symmetric_keys
from .pdf_content import extract_text_from_pdf, create_pdf_with_text


def decrypt_pdf(encrypted_pdf_bytes: bytes, key_file_bytes: bytes) -> Tuple[bytes, Dict]:
    """
    Decrypt an encrypted PDF file (full-file decryption)

    Process:
    1. Load key file and extract encrypted PDF data
    2. Load RSA private key from key file
    3. Parse metadata from key file
    4. Verify HMAC (integrity check)
    5. Decrypt symmetric keys using RSA
    6. Remove encryption layers in reverse order (dynamically based on algorithms used)
    7. Return original decrypted PDF

    Args:
        encrypted_pdf_bytes: Display PDF file (shows gibberish - not used for decryption)
        key_file_bytes: Key file content (contains actual encrypted PDF data)

    Returns:
        Tuple of (decrypted_pdf_bytes, metadata_dict)

    Raises:
        ValueError: If file format is invalid or integrity check fails
        Exception: If decryption fails (wrong key, corrupted data, etc.)
    """
    # Step 1: Load key file and get encrypted PDF data
    print(f"[DECRYPT] Loading key file...")

    # Step 2: Load key file and extract encrypted PDF data
    try:
        key_data = json.loads(key_file_bytes.decode('utf-8'))
        private_key_pem = base64.b64decode(key_data['private_key'])
        # Deserialize the PEM bytes into an RSA key object
        private_key = RSACipher.deserialize_private_key(private_key_pem)
        metadata = key_data['metadata']

        # Get the encrypted PDF data from the key file
        version = metadata.get('version', '3.0')
        if version == '4.0':
            # New version: encrypted PDF is in the key file
            ciphertext = base64.b64decode(metadata['encrypted_pdf_data'])
            print(f"[DECRYPT] Loaded encrypted PDF from key file: {len(ciphertext)} bytes")
        else:
            # Old version: need to extract from the display PDF
            print(f"[DECRYPT] Old version detected, extracting encrypted text from PDF...")
            encrypted_text, _ = extract_text_from_pdf(encrypted_pdf_bytes)
            encrypted_text_clean = encrypted_text.replace('\n', '').replace(' ', '')
            ciphertext = base64.b64decode(encrypted_text_clean)
            print(f"[DECRYPT] Decoded base64 to {len(ciphertext)} bytes")
    except (json.JSONDecodeError, KeyError) as e:
        raise ValueError(f"Invalid key file: {e}")

    # Step 3: Verify HMAC (integrity check)
    try:
        hmac_key = base64.b64decode(metadata['hmac_key'])
        expected_hmac = base64.b64decode(metadata['hmac'])
        if not HMACGenerator.verify(ciphertext, hmac_key, expected_hmac):
            raise ValueError("HMAC verification failed - file may have been tampered with")
        print(f"[DECRYPT] HMAC verification passed")
    except KeyError:
        raise ValueError("Missing HMAC data in key file")

    # Step 4: Extract encryption parameters from metadata
    try:
        encrypted_symmetric_keys = base64.b64decode(metadata['encrypted_symmetric_keys'])
        algorithms = metadata['algorithms']
        original_filename = metadata.get('original_filename', 'decrypted.pdf')
        pdf_metadata = metadata.get('pdf_metadata', {})
    except KeyError as e:
        raise ValueError(f"Missing required metadata field: {e}")

    # Step 5: Decrypt symmetric keys using RSA private key
    try:
        # For version 3.0+, we have a blob of keys
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
            elif algorithm == "DES":
                key_size = 8  # DES uses 8-byte keys
            else:  # AES-256-GCM, ChaCha20, AES-256-CBC
                key_size = 32

            symmetric_keys[f"layer{layer_num}_key"] = decrypted_keys_blob[offset:offset + key_size]
            print(f"[DECRYPT] Extracted layer{layer_num}_key for {algorithm}: offset={offset}, size={key_size} bytes")
            offset += key_size
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
                iv = base64.b64decode(metadata[f"layer{layer_num}_iv"])
                print(f"[DECRYPT] - Key length: {len(key)} bytes, IV length: {len(iv)} bytes")
                current_data = AESGCMCipher.decrypt(current_data, key, iv)
                print(f"[DECRYPT] - Success! Decrypted data size: {len(current_data)} bytes")

            elif algorithm == "AES-128-GCM":
                key = symmetric_keys[f"layer{layer_num}_key"]
                iv = base64.b64decode(metadata[f"layer{layer_num}_iv"])
                print(f"[DECRYPT] - Key length: {len(key)} bytes, IV length: {len(iv)} bytes")
                current_data = AES128GCMCipher.decrypt(current_data, key, iv)
                print(f"[DECRYPT] - Success! Decrypted data size: {len(current_data)} bytes")

            elif algorithm == "ChaCha20-Poly1305":
                key = symmetric_keys[f"layer{layer_num}_key"]
                nonce = base64.b64decode(metadata[f"layer{layer_num}_nonce"])
                print(f"[DECRYPT] - Key length: {len(key)} bytes, Nonce length: {len(nonce)} bytes")
                current_data = ChaCha20Cipher.decrypt(current_data, key, nonce)
                print(f"[DECRYPT] - Success! Decrypted data size: {len(current_data)} bytes")

            elif algorithm == "AES-256-CBC":
                key = symmetric_keys[f"layer{layer_num}_key"]
                iv = base64.b64decode(metadata[f"layer{layer_num}_iv"])
                print(f"[DECRYPT] - Key length: {len(key)} bytes, IV length: {len(iv)} bytes")
                current_data = AESCBCCipher.decrypt(current_data, key, iv)
                print(f"[DECRYPT] - Success! Decrypted data size: {len(current_data)} bytes")

            elif algorithm == "DES":
                key = symmetric_keys[f"layer{layer_num}_key"]
                iv = base64.b64decode(metadata[f"layer{layer_num}_iv"])
                print(f"[DECRYPT] - Key length: {len(key)} bytes, IV length: {len(iv)} bytes (DES - INSECURE)")
                current_data = DESCipher.decrypt(current_data, key, iv)
                print(f"[DECRYPT] - Success! Decrypted data size: {len(current_data)} bytes")

        decrypted_pdf_bytes = current_data
        print(f"[DECRYPT] All layers decrypted successfully! Decrypted PDF size: {len(decrypted_pdf_bytes)} bytes")

        # For version 4.0+, the decrypted data IS the PDF file
        if version == '4.0':
            pdf_bytes = decrypted_pdf_bytes
            print(f"[DECRYPT] Version 4.0: decrypted data is the PDF file")
        else:
            # For version 3.0 and below, convert text back and create PDF
            decrypted_text = decrypted_pdf_bytes.decode('utf-8')
            print(f"[DECRYPT] Decoded text: {len(decrypted_text)} characters")
            print(f"[DECRYPT] Creating PDF with decrypted text...")
            pdf_bytes = create_pdf_with_text(decrypted_text, pdf_metadata)
            print(f"[DECRYPT] Created decrypted PDF: {len(pdf_bytes)} bytes")

    except Exception as e:
        import traceback
        print(f"[DECRYPT ERROR] Failed at layer {layer_num} ({algorithm})")
        print(f"[DECRYPT ERROR] Exception: {type(e).__name__}: {e}")
        print(f"[DECRYPT ERROR] Traceback:\n{traceback.format_exc()}")
        raise ValueError(f"Decryption failed at layer {layer_num} ({algorithm}): {type(e).__name__}: {str(e)}")

    # Step 8: Prepare metadata for response
    response_metadata = {
        "original_filename": original_filename,
        "algorithms_used": algorithms,
        "timestamp": metadata.get('timestamp'),
        "version": version,
        "verified": True,  # HMAC passed
        "integrity_check": "PASSED"
    }

    return pdf_bytes, response_metadata


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
