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
from .area_encryption import AreaSelection, create_pdf_with_selective_encryption, get_pdf_page_info


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
        if version in ('4.0', '4.1'):
            # New version: encrypted PDF is in the key file
            ciphertext = base64.b64decode(metadata['encrypted_pdf_data'])
            print(f"[DECRYPT] Loaded encrypted PDF from key file: {len(ciphertext)} bytes")

            # For version 4.1+, verify the uploaded PDF matches the key file
            if version == '4.1':
                import hashlib
                expected_hash = metadata.get('display_pdf_hash')
                if expected_hash:
                    actual_hash = hashlib.sha256(encrypted_pdf_bytes).hexdigest()
                    if actual_hash != expected_hash:
                        print(f"[DECRYPT] Hash mismatch! Expected: {expected_hash[:16]}..., Got: {actual_hash[:16]}...")
                        raise ValueError("PDF file does not match the key file. The encrypted PDF and key file must be from the same encryption operation.")
                    print(f"[DECRYPT] Display PDF hash verification passed")
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
        if version in ('4.0', '4.1'):
            pdf_bytes = decrypted_pdf_bytes
            print(f"[DECRYPT] Version {version}: decrypted data is the PDF file")
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


def decrypt_pdf_selective(encrypted_pdf_bytes: bytes, key_file_bytes: bytes) -> Tuple[bytes, Dict]:
    """
    Decrypt a selectively encrypted PDF file

    Process:
    1. Load key file with area metadata
    2. Extract encrypted area content from key file
    3. Decrypt each area's content using symmetric keys
    4. Reconstruct PDF with original text in areas

    Args:
        encrypted_pdf_bytes: Display PDF file (shows encrypted areas)
        key_file_bytes: Key file content (contains encrypted area data)

    Returns:
        Tuple of (decrypted_pdf_bytes, metadata_dict)
    """
    print(f"[DECRYPT-SELECTIVE] Starting selective decryption...")

    # Step 1: Load key file
    try:
        key_data = json.loads(key_file_bytes.decode('utf-8'))
        private_key_pem = base64.b64decode(key_data['private_key'])
        private_key = RSACipher.deserialize_private_key(private_key_pem)
        metadata = key_data['metadata']
    except (json.JSONDecodeError, KeyError) as e:
        raise ValueError(f"Invalid key file: {e}")

    # Verify this is a selective encryption file
    encryption_type = metadata.get('encryption_type')
    version = metadata.get('version', '5.0')

    if encryption_type != 'selective':
        raise ValueError("This key file is not for selective encryption. Use standard decryption.")

    print(f"[DECRYPT-SELECTIVE] Version: {version}, Type: {encryption_type}")

    # Step 2: Extract parameters
    try:
        algorithms = metadata['algorithms']
        areas = [AreaSelection.from_dict(a) for a in metadata['areas']]
        encrypted_area_content = metadata['encrypted_area_content']
        page_info = metadata.get('page_info', {})
        original_filename = metadata.get('original_filename', 'decrypted.pdf')
    except KeyError as e:
        raise ValueError(f"Missing required metadata field: {e}")

    print(f"[DECRYPT-SELECTIVE] Areas to decrypt: {len(areas)}")
    print(f"[DECRYPT-SELECTIVE] Algorithms: {algorithms}")

    # Step 3: Decrypt symmetric keys using RSA
    encrypted_symmetric_keys = metadata.get('encrypted_symmetric_keys', '')
    if encrypted_symmetric_keys:
        encrypted_keys_bytes = base64.b64decode(encrypted_symmetric_keys)
        decrypted_keys_blob = RSACipher.decrypt(encrypted_keys_bytes, private_key)
        print(f"[DECRYPT-SELECTIVE] Decrypted keys blob: {len(decrypted_keys_blob)} bytes")
    else:
        decrypted_keys_blob = b''
        print(f"[DECRYPT-SELECTIVE] No symmetric keys to decrypt")

    # Step 4: Decrypt each area's content
    decrypted_area_text = {}

    # Calculate key sizes for extracting from blob
    key_sizes_per_area = []
    for algorithm in algorithms:
        if algorithm == "AES-128-GCM":
            key_sizes_per_area.append(16)
        elif algorithm == "DES":
            key_sizes_per_area.append(8)
        else:  # AES-256-GCM, ChaCha20, AES-256-CBC
            key_sizes_per_area.append(32)

    total_keys_per_area = sum(key_sizes_per_area)

    for area_idx, area in enumerate(areas):
        area_data = encrypted_area_content.get(area.id, {})

        if not area_data.get('encrypted_data'):
            decrypted_area_text[area.id] = "[EMPTY]"
            continue

        encrypted_bytes = base64.b64decode(area_data['encrypted_data'])
        layer_data = area_data.get('layer_data', {})

        # Extract keys for this area from the decrypted blob
        area_keys_offset = area_idx * total_keys_per_area
        area_symmetric_keys = {}
        key_offset = area_keys_offset

        for i, algorithm in enumerate(algorithms):
            layer_num = i + 1
            key_size = key_sizes_per_area[i]
            area_symmetric_keys[f"layer{layer_num}_key"] = decrypted_keys_blob[key_offset:key_offset + key_size]
            key_offset += key_size

        # Decrypt layers in reverse order
        current_data = encrypted_bytes
        print(f"[DECRYPT-SELECTIVE] Decrypting area {area.id}...")

        try:
            for i in reversed(range(len(algorithms))):
                algorithm = algorithms[i]
                layer_num = i + 1
                key = area_symmetric_keys.get(f"layer{layer_num}_key", b'')

                if algorithm == "AES-256-GCM":
                    iv = base64.b64decode(layer_data.get(f"layer{layer_num}_iv", ""))
                    current_data = AESGCMCipher.decrypt(current_data, key, iv)

                elif algorithm == "AES-128-GCM":
                    iv = base64.b64decode(layer_data.get(f"layer{layer_num}_iv", ""))
                    current_data = AES128GCMCipher.decrypt(current_data, key, iv)

                elif algorithm == "ChaCha20-Poly1305":
                    nonce = base64.b64decode(layer_data.get(f"layer{layer_num}_nonce", ""))
                    current_data = ChaCha20Cipher.decrypt(current_data, key, nonce)

                elif algorithm == "AES-256-CBC":
                    iv = base64.b64decode(layer_data.get(f"layer{layer_num}_iv", ""))
                    current_data = AESCBCCipher.decrypt(current_data, key, iv)

                elif algorithm == "DES":
                    iv = base64.b64decode(layer_data.get(f"layer{layer_num}_iv", ""))
                    current_data = DESCipher.decrypt(current_data, key, iv)

            # Decode the decrypted bytes to text
            decrypted_area_text[area.id] = current_data.decode('utf-8')
            print(f"[DECRYPT-SELECTIVE] Area {area.id} decrypted: {decrypted_area_text[area.id][:50]}...")

        except Exception as e:
            print(f"[DECRYPT-SELECTIVE] Warning: Could not decrypt area {area.id}: {e}")
            # Fallback to stored original text if decryption fails
            decrypted_area_text[area.id] = area_data.get('original_text', '[DECRYPTION FAILED]')

    print(f"[DECRYPT-SELECTIVE] Decrypted {len(decrypted_area_text)} areas")

    # Step 5: Reconstruct PDF with decrypted text overlaid on the encrypted areas
    decrypted_pdf = create_pdf_with_selective_encryption(
        encrypted_pdf_bytes,
        decrypted_area_text,
        areas,
        page_info
    )

    print(f"[DECRYPT-SELECTIVE] Created decrypted PDF: {len(decrypted_pdf)} bytes")

    # Prepare response metadata
    response_metadata = {
        "original_filename": original_filename,
        "algorithms_used": algorithms,
        "areas_decrypted": len(areas),
        "timestamp": metadata.get('timestamp'),
        "version": version,
        "encryption_type": encryption_type,
        "verified": True
    }

    return decrypted_pdf, response_metadata


def decrypt_pdf_text_search(encrypted_pdf_bytes: bytes, key_file_bytes: bytes) -> Tuple[bytes, Dict]:
    """
    Decrypt a text-search encrypted PDF file

    Process:
    1. Load key file with search term metadata
    2. Extract original PDF from key file
    3. Return the original PDF (since text search encryption stores the original)

    Args:
        encrypted_pdf_bytes: Display PDF file (shows encryption info)
        key_file_bytes: Key file content (contains original PDF)

    Returns:
        Tuple of (decrypted_pdf_bytes, metadata_dict)
    """
    print(f"[DECRYPT-TEXT-SEARCH] Starting text search decryption...")

    # Step 1: Load key file
    try:
        key_data = json.loads(key_file_bytes.decode('utf-8'))
        private_key_pem = base64.b64decode(key_data['private_key'])
        private_key = RSACipher.deserialize_private_key(private_key_pem)
        metadata = key_data['metadata']
    except (json.JSONDecodeError, KeyError) as e:
        raise ValueError(f"Invalid key file: {e}")

    # Verify this is a text search encryption file
    encryption_type = metadata.get('encryption_type')
    version = metadata.get('version', '6.0')

    if encryption_type != 'text_search':
        raise ValueError("This key file is not for text search encryption. Use standard decryption.")

    print(f"[DECRYPT-TEXT-SEARCH] Version: {version}, Type: {encryption_type}")

    # Step 2: Verify the uploaded PDF matches the key file using HMAC
    hmac_key_b64 = metadata.get('hmac_key')
    expected_hmac_b64 = metadata.get('hmac')

    if hmac_key_b64 and expected_hmac_b64:
        hmac_key = base64.b64decode(hmac_key_b64)
        expected_hmac = base64.b64decode(expected_hmac_b64)

        # Compute HMAC of the uploaded PDF
        computed_hmac = HMACGenerator.compute(encrypted_pdf_bytes, hmac_key)

        if computed_hmac != expected_hmac:
            raise ValueError("PDF file does not match the key file. The encrypted PDF and key file must be from the same encryption operation.")

        print("[DECRYPT-TEXT-SEARCH] HMAC verification passed - PDF matches key file")
    else:
        print("[DECRYPT-TEXT-SEARCH] Warning: No HMAC found in key file, skipping verification")

    # Step 3: Extract and decrypt original PDF
    try:
        # Check if using new encrypted format (v6.1+) or old plain format (v6.0)
        encrypted_original_pdf_b64 = metadata.get('encrypted_original_pdf')

        if encrypted_original_pdf_b64:
            # New format: decrypt the original PDF
            print("[DECRYPT-TEXT-SEARCH] Using encrypted original PDF format")

            encrypted_pdf_key_b64 = metadata.get('encrypted_pdf_key')
            pdf_iv_b64 = metadata.get('pdf_iv')

            if not encrypted_pdf_key_b64 or not pdf_iv_b64:
                raise ValueError("Missing encryption key or IV for original PDF")

            # Decrypt the AES key using RSA
            encrypted_pdf_key = base64.b64decode(encrypted_pdf_key_b64)
            pdf_encryption_key = RSACipher.decrypt(encrypted_pdf_key, private_key)

            # Decrypt the original PDF
            pdf_iv = base64.b64decode(pdf_iv_b64)
            encrypted_original_pdf = base64.b64decode(encrypted_original_pdf_b64)

            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import padding

            cipher = Cipher(algorithms.AES(pdf_encryption_key), modes.CBC(pdf_iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_pdf = decryptor.update(encrypted_original_pdf) + decryptor.finalize()

            # Unpad
            unpadder = padding.PKCS7(128).unpadder()
            original_pdf_bytes = unpadder.update(padded_pdf) + unpadder.finalize()

            print(f"[DECRYPT-TEXT-SEARCH] Decrypted original PDF: {len(original_pdf_bytes)} bytes")
        else:
            # Old format: plain base64 (for backward compatibility)
            original_pdf_b64 = metadata.get('original_pdf', '')
            if not original_pdf_b64:
                raise ValueError("Original PDF not found in key file")

            original_pdf_bytes = base64.b64decode(original_pdf_b64)
            print(f"[DECRYPT-TEXT-SEARCH] Restored original PDF (legacy format): {len(original_pdf_bytes)} bytes")
    except Exception as e:
        raise ValueError(f"Failed to restore original PDF: {e}")

    # Step 3: Prepare response metadata
    response_metadata = {
        "original_filename": metadata.get('original_filename', 'decrypted.pdf'),
        "algorithms_used": metadata.get('algorithms', []),
        "search_terms": metadata.get('search_terms', []),
        "occurrences": metadata.get('occurrences', {}),
        "timestamp": metadata.get('timestamp'),
        "version": version,
        "encryption_type": encryption_type,
        "verified": True
    }

    print(f"[DECRYPT-TEXT-SEARCH] Decryption complete!")
    return original_pdf_bytes, response_metadata


def decrypt_pdf_page_selection(
    encrypted_pdf_bytes: bytes,
    key_file_bytes: bytes
) -> Tuple[bytes, Dict]:
    """
    Decrypt a page-selection encrypted PDF file

    Process:
    1. Load and parse key file
    2. Return the original PDF stored in key file

    Args:
        encrypted_pdf_bytes: The encrypted PDF file (not actually used - original is in key file)
        key_file_bytes: The key file containing decryption data and original PDF

    Returns:
        Tuple of (decrypted_pdf_bytes, metadata_dict)

    Raises:
        ValueError: If key file is invalid or decryption fails
    """
    print(f"[DECRYPT-PAGE-SELECTION] Starting page selection decryption...")

    # Step 1: Parse key file
    try:
        key_data = json.loads(key_file_bytes.decode('utf-8'))
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid key file format: {e}")

    # Step 2: Extract metadata
    metadata = key_data.get('metadata', {})
    version = metadata.get('version', 'unknown')
    encryption_type = metadata.get('encryption_type', 'unknown')

    print(f"[DECRYPT-PAGE-SELECTION] Version: {version}, Type: {encryption_type}")

    if encryption_type != 'page_selection':
        raise ValueError(f"Expected page_selection encryption type, got: {encryption_type}")

    # Step 3: Verify the uploaded PDF matches the key file using HMAC
    hmac_key_b64 = metadata.get('hmac_key')
    expected_hmac_b64 = metadata.get('hmac')

    if hmac_key_b64 and expected_hmac_b64:
        hmac_key = base64.b64decode(hmac_key_b64)
        expected_hmac = base64.b64decode(expected_hmac_b64)

        # Compute HMAC of the uploaded PDF
        computed_hmac = HMACGenerator.compute(encrypted_pdf_bytes, hmac_key)

        if computed_hmac != expected_hmac:
            raise ValueError("PDF file does not match the key file. The encrypted PDF and key file must be from the same encryption operation.")

        print("[DECRYPT-PAGE-SELECTION] HMAC verification passed - PDF matches key file")
    else:
        print("[DECRYPT-PAGE-SELECTION] Warning: No HMAC found in key file, skipping verification")

    # Step 4: Get and decrypt the original PDF from key file
    # Check if using new encrypted format (v7.1+) or old plain format (v7.0)
    encrypted_original_pdf_b64 = metadata.get('encrypted_original_pdf')

    if encrypted_original_pdf_b64:
        # New format: decrypt the original PDF
        print("[DECRYPT-PAGE-SELECTION] Using encrypted original PDF format")

        # Get private key for RSA decryption
        private_key_pem = base64.b64decode(key_data['private_key'])
        private_key = RSACipher.deserialize_private_key(private_key_pem)

        encrypted_pdf_key_b64 = metadata.get('encrypted_pdf_key')
        pdf_iv_b64 = metadata.get('pdf_iv')

        if not encrypted_pdf_key_b64 or not pdf_iv_b64:
            raise ValueError("Missing encryption key or IV for original PDF")

        # Decrypt the AES key using RSA
        encrypted_pdf_key = base64.b64decode(encrypted_pdf_key_b64)
        pdf_encryption_key = RSACipher.decrypt(encrypted_pdf_key, private_key)

        # Decrypt the original PDF
        pdf_iv = base64.b64decode(pdf_iv_b64)
        encrypted_original_pdf = base64.b64decode(encrypted_original_pdf_b64)

        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import padding

        cipher = Cipher(algorithms.AES(pdf_encryption_key), modes.CBC(pdf_iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_pdf = decryptor.update(encrypted_original_pdf) + decryptor.finalize()

        # Unpad
        unpadder = padding.PKCS7(128).unpadder()
        original_pdf_bytes = unpadder.update(padded_pdf) + unpadder.finalize()

        print(f"[DECRYPT-PAGE-SELECTION] Decrypted original PDF: {len(original_pdf_bytes)} bytes")
    else:
        # Old format: plain base64 (for backward compatibility)
        original_pdf_b64 = metadata.get('original_pdf')
        if not original_pdf_b64:
            raise ValueError("Original PDF not found in key file")

        original_pdf_bytes = base64.b64decode(original_pdf_b64)
        print(f"[DECRYPT-PAGE-SELECTION] Restored original PDF (legacy format): {len(original_pdf_bytes)} bytes")

    # Step 4: Prepare response metadata
    response_metadata = {
        "original_filename": metadata.get('original_filename', 'decrypted.pdf'),
        "algorithms_used": metadata.get('algorithms', []),
        "pages_encrypted": metadata.get('pages_encrypted', []),
        "total_pages": metadata.get('total_pages', 0),
        "timestamp": metadata.get('timestamp'),
        "version": version,
        "encryption_type": encryption_type,
        "verified": True
    }

    print(f"[DECRYPT-PAGE-SELECTION] Decryption complete!")
    return original_pdf_bytes, response_metadata


__all__ = [
    'decrypt_pdf',
    'decrypt_pdf_selective',
    'decrypt_pdf_text_search',
    'decrypt_pdf_page_selection',
    'parse_encrypted_file_metadata'
]
