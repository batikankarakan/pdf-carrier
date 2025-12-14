"""
Encryption Module

Implements the complete PDF encryption workflow:
1. Extract text content from PDF
2. Encrypt the text content with selected algorithms
3. Create new PDF with encrypted text content
4. Generate encryption keys
5. Randomly select algorithms
6. Apply multiple encryption layers to text
7. Create encrypted file with metadata
8. Generate key file for distribution
"""

import json
import random
import base64
import os
from datetime import datetime
from typing import Dict, List, Tuple
from .algorithms import AESGCMCipher, AES128GCMCipher, AESCBCCipher, ChaCha20Cipher, DESCipher, RSACipher, HMACGenerator
from .cryptography import CascadingEntropyMixer

# Global key generator instance for encryption operations
_key_generator = CascadingEntropyMixer(rounds=7, pool_size=64)
from .key_management import (
    generate_encryption_keys,
    create_key_file,
    encapsulate_symmetric_keys
)
from .pdf_content import get_pdf_metadata, create_pdf_with_text


# Available encryption algorithms
AVAILABLE_ALGORITHMS = [
    "AES-256-GCM",
    "AES-128-GCM",
    "ChaCha20-Poly1305",
    "AES-256-CBC",
    "DES"  # WARNING: Insecure - academic purposes only
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


def encrypt_pdf(pdf_bytes: bytes, original_filename: str, algorithms: List[str] = None) -> Tuple[bytes, bytes]:
    """
    Encrypt entire PDF file with multi-layer encryption while creating a displayable encrypted PDF

    Process:
    1. Get PDF metadata (page count, sizes)
    2. Generate all encryption keys
    3. Use provided algorithms or randomly select 2 encryption algorithms
    4. Apply Layer 1: First selected algorithm on entire PDF file
    5. Apply Layer 2: Second selected algorithm on encrypted data
    6. Create new PDF showing the encrypted content (base64 gibberish)
    7. Encapsulate symmetric keys with RSA
    8. Create key file with encrypted PDF and metadata
    9. Generate downloadable key file

    Args:
        pdf_bytes: PDF file content
        original_filename: Name of the original file
        algorithms: Optional list of algorithm names to use (must be exactly 2)

    Returns:
        Tuple of (encrypted_pdf_bytes, key_file_bytes)
    """
    # Step 1: Get PDF metadata (for creating display PDF with similar layout)
    print(f"[ENCRYPT] Getting PDF metadata...")
    pdf_metadata = get_pdf_metadata(pdf_bytes)
    print(f"[ENCRYPT] PDF has {pdf_metadata['page_count']} pages")

    # Use the entire PDF file as the data to encrypt
    print(f"[ENCRYPT] Input PDF size: {len(pdf_bytes)} bytes")

    # Step 2: Generate all encryption keys
    keys = generate_encryption_keys()
    rsa_private = keys['rsa_private']
    rsa_public = keys['rsa_public']

    # Step 3: Use provided algorithms or randomly select 2
    if algorithms:
        if len(algorithms) != 2:
            raise ValueError("Must provide exactly 2 algorithms")
        if not all(algo in AVAILABLE_ALGORITHMS for algo in algorithms):
            raise ValueError(f"Invalid algorithms. Available: {AVAILABLE_ALGORITHMS}")
        selected_algorithms = algorithms
        print(f"[ENCRYPT] Using user-selected algorithms: {selected_algorithms}")
    else:
        selected_algorithms = select_random_algorithms(2)
        print(f"[ENCRYPT] Randomly selected algorithms: {selected_algorithms}")

    # Step 4 & 5: Apply encryption layers dynamically based on selected algorithms
    # Generate keys and store IVs/nonces for each algorithm
    layer_data = {}
    symmetric_keys = {}

    current_data = pdf_bytes  # Encrypt the entire PDF file

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

        elif algorithm == "DES":
            key = DESCipher.generate_key()
            print(f"[ENCRYPT] - Generated key: {len(key)} bytes (DES - INSECURE)")
            ciphertext, iv, _ = DESCipher.encrypt(current_data, key)
            print(f"[ENCRYPT] - Success! Encrypted data size: {len(ciphertext)} bytes")
            layer_data[f"layer{layer_num}_iv"] = base64.b64encode(iv).decode('utf-8')
            symmetric_keys[f"layer{layer_num}_key"] = key
            current_data = ciphertext

    ciphertext_final = current_data
    print(f"[ENCRYPT] All layers encrypted. Final size: {len(ciphertext_final)} bytes")

    # Step 6: Convert encrypted bytes to base64 text representation
    encrypted_text = base64.b64encode(ciphertext_final).decode('utf-8')
    # Format it nicely for PDF display (wrap at 64 chars)
    chunk_size = 64
    encrypted_text_formatted = '\n'.join([encrypted_text[i:i+chunk_size] for i in range(0, len(encrypted_text), chunk_size)])
    print(f"[ENCRYPT] Created formatted encrypted text: {len(encrypted_text_formatted)} characters")

    # Step 7: Create new PDF with encrypted text
    print(f"[ENCRYPT] Creating PDF with encrypted text...")
    encrypted_pdf_bytes = create_pdf_with_text(encrypted_text_formatted, pdf_metadata)
    print(f"[ENCRYPT] Created encrypted PDF: {len(encrypted_pdf_bytes)} bytes")

    # Step 8: Encapsulate symmetric keys with RSA
    # Combine all symmetric keys into one blob
    keys_blob = b''.join([symmetric_keys[f"layer{i+1}_key"] for i in range(len(selected_algorithms))])
    print(f"[ENCRYPT] Created keys blob:")
    for i in range(len(selected_algorithms)):
        key = symmetric_keys[f"layer{i+1}_key"]
        print(f"[ENCRYPT] - Layer {i+1} ({selected_algorithms[i]}): {len(key)} bytes")
    print(f"[ENCRYPT] Total keys blob size: {len(keys_blob)} bytes")

    # Encrypt the keys blob directly with RSA
    encrypted_symmetric_keys = RSACipher.encrypt(keys_blob, rsa_public)
    print(f"[ENCRYPT] Encrypted keys blob size: {len(encrypted_symmetric_keys)} bytes")

    # Step 9: Generate HMAC for integrity verification
    hmac_key = HMACGenerator.generate_key()
    hmac_tag = HMACGenerator.compute(ciphertext_final, hmac_key)

    # Step 9b: Generate hash of the display PDF for verification during decryption
    import hashlib
    display_pdf_hash = hashlib.sha256(encrypted_pdf_bytes).hexdigest()
    print(f"[ENCRYPT] Display PDF hash: {display_pdf_hash[:16]}...")

    # Step 10: Store the encrypted PDF in the key file
    # The key file will contain the actual encrypted PDF data
    metadata = {
        "version": "4.1",  # Updated version with display PDF verification
        "algorithms": selected_algorithms,
        "encrypted_symmetric_keys": base64.b64encode(encrypted_symmetric_keys).decode('utf-8'),
        "encrypted_pdf_data": base64.b64encode(ciphertext_final).decode('utf-8'),  # Store encrypted PDF here
        "display_pdf_hash": display_pdf_hash,  # Hash of the display PDF for verification
        "hmac_key": base64.b64encode(hmac_key).decode('utf-8'),
        "hmac": base64.b64encode(hmac_tag).decode('utf-8'),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "original_filename": original_filename,
        "pdf_metadata": pdf_metadata
    }

    # Add layer-specific IVs/nonces to metadata
    metadata.update(layer_data)

    # Step 11: Create key file
    # Serialize RSA keys to PEM format
    private_key_pem = RSACipher.serialize_private_key(rsa_private)
    public_key_pem = RSACipher.serialize_public_key(rsa_public)

    key_file_data = {
        "private_key": base64.b64encode(private_key_pem).decode('utf-8'),
        "public_key": base64.b64encode(public_key_pem).decode('utf-8'),
        "metadata": metadata
    }
    key_file_bytes = json.dumps(key_file_data, indent=2).encode('utf-8')

    return encrypted_pdf_bytes, key_file_bytes


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


def create_encrypted_pages_pdf(reader, encrypted_pages_list: List[int], encrypted_pages_data: dict) -> bytes:
    """
    Create a PDF where selected pages are replaced with encrypted content display.
    Non-selected pages remain as original.

    Args:
        reader: PdfReader of the original PDF
        encrypted_pages_list: List of page numbers that were encrypted (1-indexed)
        encrypted_pages_data: Dict with encrypted data for each page

    Returns:
        PDF bytes with encrypted pages showing gibberish
    """
    from pypdf import PdfWriter
    from reportlab.pdfgen import canvas
    from reportlab.lib.colors import black
    import io

    writer = PdfWriter()

    for page_num, page in enumerate(reader.pages, 1):
        if page_num in encrypted_pages_list:
            # Create a replacement page showing encrypted content
            page_width = float(page.mediabox.width)
            page_height = float(page.mediabox.height)

            # Get the encrypted data for this page
            page_data = encrypted_pages_data.get(str(page_num), {})
            encrypted_b64 = page_data.get('encrypted_data', 'ENCRYPTED')[:2000]  # Truncate for display

            # Create new page with encrypted content
            packet = io.BytesIO()
            c = canvas.Canvas(packet, pagesize=(page_width, page_height))

            # Draw encrypted gibberish
            c.setFont('Courier', 8)
            y_pos = page_height - 40
            line_height = 10
            chars_per_line = int((page_width - 80) / 4.8)  # Approximate for Courier 8pt

            # Fill the page with encrypted content
            pos = 0
            while y_pos > 40 and pos < len(encrypted_b64):
                line = encrypted_b64[pos:pos + chars_per_line]
                c.drawString(40, y_pos, line)
                y_pos -= line_height
                pos += chars_per_line

            c.save()
            packet.seek(0)

            # Read the generated page and add to writer
            from pypdf import PdfReader as PR
            new_page_reader = PR(packet)
            writer.add_page(new_page_reader.pages[0])
        else:
            # Keep original page
            writer.add_page(page)

    # Write output
    output = io.BytesIO()
    writer.write(output)
    output.seek(0)
    return output.read()


def encrypt_pdf_page_selection(
    pdf_bytes: bytes,
    pages: List[int],
    original_filename: str,
    algorithms: List[str] = None
) -> Tuple[bytes, bytes]:
    """
    Encrypt specific pages of a PDF

    Process:
    1. Extract selected pages
    2. Encrypt each selected page's content
    3. Create PDF with encrypted pages (showing encrypted content)
    4. Store original pages in key file for decryption

    Args:
        pdf_bytes: PDF file content
        pages: List of page numbers to encrypt (1-indexed)
        original_filename: Name of the original file
        algorithms: Optional list of algorithm names to use (must be exactly 2)

    Returns:
        Tuple of (encrypted_pdf_bytes, key_file_bytes)
    """
    from pypdf import PdfReader, PdfWriter
    import io

    print(f"[ENCRYPT-PAGE-SELECTION] Starting page selection encryption...")
    print(f"[ENCRYPT-PAGE-SELECTION] Pages to encrypt: {pages}")

    # Read the PDF
    reader = PdfReader(io.BytesIO(pdf_bytes))
    total_pages = len(reader.pages)

    # Validate page numbers
    for page_num in pages:
        if page_num < 1 or page_num > total_pages:
            raise ValueError(f"Invalid page number {page_num}. PDF has {total_pages} pages.")

    # Step 1: Generate keys
    keys = generate_encryption_keys()
    rsa_private = keys['rsa_private']
    rsa_public = keys['rsa_public']

    # Step 2: Select algorithms
    if algorithms:
        if len(algorithms) != 2:
            raise ValueError("Must provide exactly 2 algorithms")
        if not all(algo in AVAILABLE_ALGORITHMS for algo in algorithms):
            raise ValueError(f"Invalid algorithms. Available: {AVAILABLE_ALGORITHMS}")
        selected_algorithms = algorithms
        print(f"[ENCRYPT-PAGE-SELECTION] Using user-selected algorithms: {selected_algorithms}")
    else:
        selected_algorithms = select_random_algorithms(2)
        print(f"[ENCRYPT-PAGE-SELECTION] Randomly selected algorithms: {selected_algorithms}")

    # Step 3: Extract and encrypt each selected page's bytes
    encrypted_pages = {}
    layer_data = {}
    symmetric_keys = {}

    for page_num in pages:
        # Extract the page as a separate PDF
        page_writer = PdfWriter()
        page_writer.add_page(reader.pages[page_num - 1])  # 0-indexed

        page_buffer = io.BytesIO()
        page_writer.write(page_buffer)
        page_bytes = page_buffer.getvalue()

        # Encrypt the page bytes
        current_data = page_bytes
        page_layer_data = {}
        page_symmetric_keys = {}

        for i, algorithm in enumerate(selected_algorithms):
            layer_num = i + 1

            if algorithm == "AES-256-GCM":
                key = AESGCMCipher.generate_key()
                ciphertext, iv = AESGCMCipher.encrypt(current_data, key)
                page_layer_data[f"layer{layer_num}_iv"] = base64.b64encode(iv).decode('utf-8')
                page_symmetric_keys[f"layer{layer_num}_key"] = key
                current_data = ciphertext

            elif algorithm == "AES-128-GCM":
                key = AES128GCMCipher.generate_key()
                ciphertext, iv = AES128GCMCipher.encrypt(current_data, key)
                page_layer_data[f"layer{layer_num}_iv"] = base64.b64encode(iv).decode('utf-8')
                page_symmetric_keys[f"layer{layer_num}_key"] = key
                current_data = ciphertext

            elif algorithm == "ChaCha20-Poly1305":
                key = ChaCha20Cipher.generate_key()
                ciphertext, nonce = ChaCha20Cipher.encrypt(current_data, key)
                page_layer_data[f"layer{layer_num}_nonce"] = base64.b64encode(nonce).decode('utf-8')
                page_symmetric_keys[f"layer{layer_num}_key"] = key
                current_data = ciphertext

            elif algorithm == "AES-256-CBC":
                key = AESCBCCipher.generate_key()
                ciphertext, iv, _ = AESCBCCipher.encrypt(current_data, key)
                page_layer_data[f"layer{layer_num}_iv"] = base64.b64encode(iv).decode('utf-8')
                page_symmetric_keys[f"layer{layer_num}_key"] = key
                current_data = ciphertext

            elif algorithm == "DES":
                key = DESCipher.generate_key()
                ciphertext, iv, _ = DESCipher.encrypt(current_data, key)
                page_layer_data[f"layer{layer_num}_iv"] = base64.b64encode(iv).decode('utf-8')
                page_symmetric_keys[f"layer{layer_num}_key"] = key
                current_data = ciphertext

        # Store encrypted page data
        encrypted_pages[str(page_num)] = {
            'encrypted_data': base64.b64encode(current_data).decode('utf-8'),
            'original_page_bytes': base64.b64encode(page_bytes).decode('utf-8'),
            'layer_data': page_layer_data
        }

        layer_data[str(page_num)] = page_layer_data
        symmetric_keys[str(page_num)] = page_symmetric_keys

    print(f"[ENCRYPT-PAGE-SELECTION] Encrypted {len(encrypted_pages)} pages")

    # Step 4: Create output PDF with encrypted pages replaced
    encrypted_pdf = create_encrypted_pages_pdf(reader, pages, encrypted_pages)
    print(f"[ENCRYPT-PAGE-SELECTION] Created encrypted PDF: {len(encrypted_pdf)} bytes")

    # Step 5: Create combined keys blob for RSA encryption
    all_keys = b''
    for page_num in pages:
        if str(page_num) in symmetric_keys:
            for i in range(len(selected_algorithms)):
                key = symmetric_keys[str(page_num)].get(f"layer{i+1}_key", b'')
                all_keys += key

    # Encrypt the keys blob with RSA
    if all_keys:
        encrypted_symmetric_keys = RSACipher.encrypt(all_keys, rsa_public)
    else:
        encrypted_symmetric_keys = b''

    # Step 6: Generate HMAC for integrity
    hmac_key = HMACGenerator.generate_key()
    hmac_tag = HMACGenerator.compute(encrypted_pdf, hmac_key)

    # Step 7: Encrypt the original PDF for secure storage using CEM algorithm
    pdf_encryption_key = _key_generator.generate_key(32)  # 256-bit key for AES
    pdf_iv = _key_generator.generate_key(16)  # IV for AES

    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding

    # Pad the PDF bytes
    padder = padding.PKCS7(128).padder()
    padded_pdf = padder.update(pdf_bytes) + padder.finalize()

    # Encrypt
    cipher = Cipher(algorithms.AES(pdf_encryption_key), modes.CBC(pdf_iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_original_pdf = encryptor.update(padded_pdf) + encryptor.finalize()

    # Encrypt the PDF encryption key with RSA
    encrypted_pdf_key = RSACipher.encrypt(pdf_encryption_key, rsa_public)

    print(f"[ENCRYPT-PAGE-SELECTION] Original PDF encrypted: {len(encrypted_original_pdf)} bytes")

    # Step 8: Create metadata
    metadata = {
        "version": "7.1",  # Updated version for encrypted original PDF
        "encryption_type": "page_selection",
        "algorithms": selected_algorithms,
        "encrypted_symmetric_keys": base64.b64encode(encrypted_symmetric_keys).decode('utf-8') if encrypted_symmetric_keys else '',
        "pages_encrypted": pages,
        "total_pages": total_pages,
        "encrypted_pages": encrypted_pages,
        "hmac_key": base64.b64encode(hmac_key).decode('utf-8'),
        "hmac": base64.b64encode(hmac_tag).decode('utf-8'),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "original_filename": original_filename,
        "encrypted_original_pdf": base64.b64encode(encrypted_original_pdf).decode('utf-8'),  # Encrypted original
        "encrypted_pdf_key": base64.b64encode(encrypted_pdf_key).decode('utf-8'),  # RSA-encrypted AES key
        "pdf_iv": base64.b64encode(pdf_iv).decode('utf-8')  # IV for AES decryption
    }

    # Step 8: Create key file
    private_key_pem = RSACipher.serialize_private_key(rsa_private)
    public_key_pem = RSACipher.serialize_public_key(rsa_public)

    key_file_data = {
        "private_key": base64.b64encode(private_key_pem).decode('utf-8'),
        "public_key": base64.b64encode(public_key_pem).decode('utf-8'),
        "metadata": metadata
    }
    key_file_bytes = json.dumps(key_file_data, indent=2).encode('utf-8')

    print(f"[ENCRYPT-PAGE-SELECTION] Encryption complete!")
    return encrypted_pdf, key_file_bytes


__all__ = [
    'encrypt_pdf',
    'encrypt_pdf_page_selection',
    'select_random_algorithms',
    'get_encryption_info',
    'AVAILABLE_ALGORITHMS'
]
