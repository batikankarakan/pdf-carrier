# PDF Carrier - Backend API

FastAPI backend implementing secure PDF encryption/decryption with hybrid cryptography.

## Features

- **Hybrid Encryption**: RSA-4096 + AES-256-GCM + ChaCha20-Poly1305
- **Multi-layer Security**: Multiple encryption algorithms applied sequentially
- **Authenticated Encryption**: Prevents tampering with AES-GCM, ChaCha20-Poly1305, and HMAC
- **Perfect Forward Secrecy**: Unique keys for each encryption
- **Kerckhoffs's Principle**: Algorithm metadata stored in file header

## Setup

### Prerequisites

- Python 3.10+
- pip

### Installation

```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Run Development Server

```bash
python main.py
```

Or using uvicorn directly:

```bash
uvicorn main:app --reload --port 8000
```

The API will be available at: **http://localhost:8000**

API Documentation: **http://localhost:8000/docs**

## API Endpoints

### GET /api/health
Health check

### GET /api/algorithms
List available encryption algorithms

### POST /api/encrypt
Encrypt a PDF file
- **Body**: `multipart/form-data` with `file` field
- **Returns**: Encrypted file + key file (base64)

### POST /api/decrypt
Decrypt a PDF file
- **Body**: `multipart/form-data` with `encrypted_file` and `key_file` fields
- **Returns**: Decrypted PDF (base64)

### POST /api/metadata
Get metadata from encrypted file without decrypting

## Project Structure

```
backend/
├── main.py                  # FastAPI application
├── requirements.txt         # Python dependencies
├── crypto/
│   ├── algorithms.py        # AES, ChaCha20, RSA, HMAC
│   ├── encryption.py        # Encryption workflow
│   ├── decryption.py        # Decryption workflow
│   └── key_management.py    # Key generation and handling
├── models/
│   └── schemas.py           # (Future: Pydantic models)
└── utils/
    └── file_handler.py      # (Future: File operations)
```

## Security Implementation

### Encryption Process:
1. Generate random AES-256 and ChaCha20 keys
2. Generate RSA-4096 keypair
3. Randomly select 2 algorithms
4. Encrypt PDF with AES-256-GCM (Layer 1)
5. Encrypt result with ChaCha20-Poly1305 (Layer 2)
6. Encrypt symmetric keys with RSA public key
7. Compute HMAC for integrity
8. Create JSON file with metadata + ciphertext

### Decryption Process:
1. Parse JSON file and extract metadata
2. Load RSA private key from key file
3. Verify HMAC (detects tampering)
4. Decrypt symmetric keys with RSA
5. Decrypt Layer 2 (ChaCha20)
6. Decrypt Layer 1 (AES)
7. Return original PDF

## Testing

### Using curl:

**Encrypt:**
```bash
curl -X POST "http://localhost:8000/api/encrypt" \
  -F "file=@document.pdf" \
  -o response.json
```

**Decrypt:**
```bash
curl -X POST "http://localhost:8000/api/decrypt" \
  -F "encrypted_file=@encrypted.pdf" \
  -F "key_file=@key.json" \
  -o response.json
```

### Using Python:

```python
import requests
import base64

# Encrypt
with open('document.pdf', 'rb') as f:
    response = requests.post(
        'http://localhost:8000/api/encrypt',
        files={'file': f}
    )
    data = response.json()

    # Save encrypted file
    with open('encrypted.pdf', 'wb') as ef:
        ef.write(base64.b64decode(data['encrypted_file']))

    # Save key file
    with open('key.json', 'wb') as kf:
        kf.write(base64.b64decode(data['key_file']))
```

## Dependencies

- **fastapi**: Web framework
- **uvicorn**: ASGI server
- **cryptography**: Cryptographic primitives
- **python-multipart**: File upload support
- **pydantic**: Data validation
- **python-dotenv**: Environment variables

## Current Status

✅ **Implemented:**
- Complete cryptographic core
- All encryption algorithms
- Key management
- FastAPI endpoints
- CORS configuration
- Error handling

⏳ **Next:**
- Frontend integration
- End-to-end testing
- Performance optimization

---

Built for Cryptography Course Project
