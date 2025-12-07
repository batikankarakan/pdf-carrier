"""
Test script for PDF content encryption/decryption
"""
import requests
import base64
import json

# API endpoint
BASE_URL = "http://localhost:8000"

def test_encryption():
    """Test PDF content encryption"""
    print("=" * 60)
    print("TESTING PDF CONTENT ENCRYPTION")
    print("=" * 60)

    # Read the test PDF
    pdf_path = "test_document.pdf"
    print(f"\n1. Reading PDF file: {pdf_path}")

    with open(pdf_path, 'rb') as f:
        pdf_bytes = f.read()
    print(f"   PDF size: {len(pdf_bytes)} bytes")

    # Encrypt the PDF
    print("\n2. Encrypting PDF content...")
    files = {
        'file': ('test_document.pdf', pdf_bytes, 'application/pdf')
    }

    response = requests.post(f"{BASE_URL}/api/encrypt", files=files)

    if response.status_code != 200:
        print(f"   ERROR: {response.status_code}")
        print(f"   {response.text}")
        return None, None

    result = response.json()
    print(f"   Success!")
    print(f"   Algorithms used: {result['algorithms']}")

    # Decode and save encrypted PDF
    encrypted_pdf = base64.b64decode(result['encrypted_file'])
    encrypted_pdf_path = "encrypted_content.pdf"
    with open(encrypted_pdf_path, 'wb') as f:
        f.write(encrypted_pdf)
    print(f"   Saved encrypted PDF: {encrypted_pdf_path} ({len(encrypted_pdf)} bytes)")

    # Save key file
    key_file = base64.b64decode(result['key_file'])
    key_file_path = "key_content.json"
    with open(key_file_path, 'wb') as f:
        f.write(key_file)
    print(f"   Saved key file: {key_file_path}")

    return encrypted_pdf_path, key_file_path


def test_decryption(encrypted_pdf_path, key_file_path):
    """Test PDF content decryption"""
    print("\n" + "=" * 60)
    print("TESTING PDF CONTENT DECRYPTION")
    print("=" * 60)

    # Read encrypted PDF and key file
    print(f"\n1. Reading encrypted PDF and key file...")
    with open(encrypted_pdf_path, 'rb') as f:
        encrypted_pdf = f.read()
    with open(key_file_path, 'rb') as f:
        key_file = f.read()

    print(f"   Encrypted PDF: {len(encrypted_pdf)} bytes")
    print(f"   Key file: {len(key_file)} bytes")

    # Decrypt
    print("\n2. Decrypting PDF content...")
    files = {
        'encrypted_file': ('encrypted.pdf', encrypted_pdf, 'application/pdf'),
        'key_file': ('key.json', key_file, 'application/json')
    }

    response = requests.post(f"{BASE_URL}/api/decrypt", files=files)

    if response.status_code != 200:
        print(f"   ERROR: {response.status_code}")
        print(f"   {response.text}")
        return

    result = response.json()
    print(f"   Success!")
    print(f"   Algorithms used: {result['metadata']['algorithms_used']}")
    print(f"   Integrity check: {result['metadata']['integrity_check']}")

    # Save decrypted PDF
    decrypted_pdf = base64.b64decode(result['decrypted_file'])
    decrypted_pdf_path = "decrypted_content.pdf"
    with open(decrypted_pdf_path, 'wb') as f:
        f.write(decrypted_pdf)
    print(f"   Saved decrypted PDF: {decrypted_pdf_path} ({len(decrypted_pdf)} bytes)")

    print("\n" + "=" * 60)
    print("TEST COMPLETE!")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Open 'encrypted_content.pdf' - you should see encrypted gibberish")
    print("2. Open 'decrypted_content.pdf' - you should see the original text")


if __name__ == "__main__":
    # Run encryption test
    encrypted_pdf_path, key_file_path = test_encryption()

    if encrypted_pdf_path and key_file_path:
        # Run decryption test
        test_decryption(encrypted_pdf_path, key_file_path)
