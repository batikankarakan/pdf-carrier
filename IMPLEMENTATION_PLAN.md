# PDF-Carrier: Secure File Encryption System - Implementation Plan

## Project Overview

### Purpose
A secure file sharing system for PDF files that demonstrates advanced cryptographic concepts including:
- Hybrid encryption architecture
- Multiple encryption algorithm layers
- Proper key management and distribution
- Cryptographic integrity verification

### Core Concepts Demonstrated
1. **Kerckhoffs's Principle**: Security relies on key secrecy, not algorithm secrecy
2. **Hybrid Encryption**: Combining asymmetric and symmetric encryption
3. **Defense in Depth**: Multiple encryption layers
4. **Authenticated Encryption**: Ensuring both confidentiality and integrity

## Architecture Overview

```
┌─────────────────┐
│   Vue.js SPA    │  ✅ COMPLETED
│  (Frontend UI)  │
└────────┬────────┘
         │ HTTP/REST
         ▼
┌─────────────────┐
│  FastAPI Server │  ⏳ NEXT PHASE
│  (Backend API)  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Cryptography    │
│ Library         │
│ (Python)        │
└─────────────────┘
```

### Technology Stack

**Frontend (✅ COMPLETED):**
- Vue 3 (Composition API)
- Vite (build tool)
- Vue Router (routing)
- Axios (HTTP client)
- TailwindCSS v3.4 (styling)

**Backend (⏳ TO BE IMPLEMENTED):**
- Python 3.10+
- FastAPI (REST API framework)
- cryptography library (FIPS 140-2 compliant)
- PyPDF2 (PDF handling)
- uvicorn (ASGI server)

## Current Project Status

### ✅ Phase 1: Frontend (COMPLETED)

**Completed Components:**
- [x] Vue 3 project setup with Vite
- [x] TailwindCSS v3.4 configuration
- [x] Vue Router setup (Encrypt/Decrypt routes)
- [x] Main App layout with navigation header/footer
- [x] FileUpload component (drag & drop, validation)
- [x] SecurityIndicator component (visual security display)
- [x] EncryptView page (full encryption UI)
- [x] DecryptView page (full decryption UI)
- [x] API service layer ready for backend integration
- [x] Responsive design (mobile & desktop)
- [x] Animations and polish
- [x] Frontend documentation

**Frontend File Structure:**
```
frontend/
├── src/
│   ├── components/
│   │   ├── FileUpload.vue           ✅
│   │   └── SecurityIndicator.vue    ✅
│   ├── views/
│   │   ├── EncryptView.vue          ✅
│   │   └── DecryptView.vue          ✅
│   ├── router/
│   │   └── index.js                 ✅
│   ├── services/
│   │   └── api.js                   ✅
│   ├── App.vue                      ✅
│   ├── main.js                      ✅
│   └── style.css                    ✅
├── tailwind.config.js               ✅
├── postcss.config.js                ✅
├── vite.config.js                   ✅
├── package.json                     ✅
├── .env.example                     ✅
└── README.md                        ✅
```

### ⏳ Phase 2: Backend Implementation (NEXT)

## Backend Implementation Roadmap

### Step 1: Project Setup

**Create Backend Structure:**
```bash
backend/
├── main.py                    # FastAPI application entry
├── requirements.txt           # Python dependencies
├── .env.example              # Environment variables template
├── config.py                 # Configuration management
├── crypto/
│   ├── __init__.py
│   ├── encryption.py         # Encryption logic
│   ├── decryption.py         # Decryption logic
│   ├── key_management.py     # Key generation & handling
│   ├── algorithms.py         # Algorithm implementations
│   └── utils.py              # Crypto utilities
├── models/
│   ├── __init__.py
│   └── schemas.py            # Pydantic models
└── utils/
    ├── __init__.py
    └── file_handler.py       # File operations
```

**Dependencies (requirements.txt):**
```
fastapi==0.104.1
uvicorn[standard]==0.24.0
python-multipart==0.0.6
cryptography==41.0.7
PyPDF2==3.0.1
python-dotenv==1.0.0
pydantic==2.5.0
python-jose[cryptography]==3.3.0
```

### Step 2: FastAPI Application Setup

**Endpoints to Implement:**

1. **POST /api/encrypt**
   - Accept PDF file upload
   - Generate encryption keys
   - Randomly select 2 algorithms
   - Apply encryption layers
   - Return encrypted file + key file (base64 or download)

2. **POST /api/decrypt**
   - Accept encrypted PDF + key file
   - Parse metadata header
   - Verify integrity (HMAC)
   - Decrypt layers in reverse
   - Return original PDF

3. **GET /api/algorithms**
   - Return list of available encryption algorithms
   - Include descriptions

4. **GET /api/health**
   - Health check endpoint

**CORS Configuration:**
```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### Step 3: Cryptographic Implementation

**crypto/algorithms.py:**

Implement these encryption algorithms:

1. **AES-256-GCM**
   - 256-bit key
   - 96-bit IV (randomly generated)
   - Authenticated encryption

2. **ChaCha20-Poly1305**
   - 256-bit key
   - 96-bit nonce (randomly generated)
   - Authenticated encryption

3. **RSA-OAEP**
   - 4096-bit key pair
   - SHA-256 hash
   - For key encapsulation

4. **HMAC-SHA256**
   - For file integrity verification

**crypto/key_management.py:**

Functions to implement:
- `generate_rsa_keypair(key_size=4096)` - Generate RSA keys
- `generate_symmetric_key(algorithm)` - Generate AES/ChaCha20 keys
- `export_key_file(private_key, metadata)` - Create downloadable key file (JSON)
- `import_key_file(key_file_content)` - Load key from uploaded file

**crypto/encryption.py:**

Main encryption workflow:
```python
def encrypt_pdf(pdf_file_bytes):
    # 1. Read PDF file
    # 2. Generate random symmetric keys (AES + ChaCha20)
    # 3. Randomly select 2 algorithms
    # 4. Apply Layer 1: AES-256-GCM encryption
    # 5. Apply Layer 2: ChaCha20-Poly1305 encryption
    # 6. Generate RSA key pair
    # 7. Encrypt symmetric keys with RSA public key
    # 8. Create file header with metadata
    # 9. Compute HMAC for integrity
    # 10. Return encrypted file + key file
```

**crypto/decryption.py:**

Main decryption workflow:
```python
def decrypt_pdf(encrypted_file_bytes, key_file):
    # 1. Parse file header metadata
    # 2. Extract algorithm information
    # 3. Load private key from key file
    # 4. Verify HMAC (integrity check)
    # 5. Decrypt symmetric keys with RSA
    # 6. Remove Layer 2: ChaCha20-Poly1305
    # 7. Remove Layer 1: AES-256-GCM
    # 8. Return original PDF
```

### Step 4: File Format Specifications

**Encrypted File Structure:**
```json
{
  "header": {
    "version": "1.0",
    "algorithms": ["AES-256-GCM", "ChaCha20-Poly1305"],
    "aes_iv": "<base64>",
    "chacha_nonce": "<base64>",
    "encrypted_symmetric_keys": "<base64>",
    "salt": "<base64>",
    "timestamp": "2025-10-26T...",
    "original_filename": "document.pdf"
  },
  "ciphertext": "<base64>",
  "hmac": "<base64>"
}
```

**Key File Structure (JSON):**
```json
{
  "version": "1.0",
  "key_type": "RSA_PRIVATE",
  "private_key_pem": "<PEM encoded>",
  "public_key_pem": "<PEM encoded>",
  "key_size": 4096,
  "created_at": "2025-10-26T...",
  "key_id": "<UUID>",
  "algorithm_pool": ["AES-256-GCM", "ChaCha20-Poly1305"]
}
```

### Step 5: Implementation Details

**Random Algorithm Selection:**
```python
import random
from typing import List

AVAILABLE_ALGORITHMS = [
    "AES-256-GCM",
    "ChaCha20-Poly1305"
]

def select_random_algorithms(count: int = 2) -> List[str]:
    """Randomly select encryption algorithms"""
    return random.sample(AVAILABLE_ALGORITHMS, count)
```

**Key Generation:**
```python
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import secrets

def generate_rsa_keypair():
    """Generate 4096-bit RSA key pair"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )
    public_key = private_key.public_key()
    return private_key, public_key

def generate_aes_key():
    """Generate 256-bit AES key"""
    return secrets.token_bytes(32)  # 32 bytes = 256 bits

def generate_chacha20_key():
    """Generate 256-bit ChaCha20 key"""
    return secrets.token_bytes(32)
```

**AES-256-GCM Encryption:**
```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def encrypt_aes_gcm(plaintext: bytes, key: bytes):
    """Encrypt with AES-256-GCM"""
    aesgcm = AESGCM(key)
    iv = os.urandom(12)  # 96 bits
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    return ciphertext, iv
```

**ChaCha20-Poly1305 Encryption:**
```python
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def encrypt_chacha20(plaintext: bytes, key: bytes):
    """Encrypt with ChaCha20-Poly1305"""
    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(12)  # 96 bits
    ciphertext = chacha.encrypt(nonce, plaintext, None)
    return ciphertext, nonce
```

**RSA Key Encapsulation:**
```python
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import json

def encapsulate_keys(symmetric_keys: dict, public_key):
    """Encrypt symmetric keys with RSA"""
    keys_json = json.dumps(symmetric_keys).encode()
    encrypted_keys = public_key.encrypt(
        keys_json,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_keys
```

**HMAC Generation:**
```python
from cryptography.hazmat.primitives import hmac, hashes

def compute_hmac(data: bytes, key: bytes):
    """Compute HMAC-SHA256"""
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()
```

### Step 6: FastAPI Endpoints Implementation

**main.py:**
```python
from fastapi import FastAPI, UploadFile, File
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import base64

app = FastAPI(title="PDF Carrier API")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/api/encrypt")
async def encrypt_file(file: UploadFile = File(...)):
    """Encrypt a PDF file"""
    # 1. Read uploaded file
    pdf_bytes = await file.read()

    # 2. Perform encryption
    encrypted_data, key_data = encrypt_pdf(pdf_bytes)

    # 3. Return base64 encoded files
    return JSONResponse({
        "success": True,
        "algorithms": encrypted_data["algorithms"],
        "encrypted_file": base64.b64encode(encrypted_data["file"]).decode(),
        "key_file": base64.b64encode(key_data).decode(),
        "timestamp": encrypted_data["timestamp"],
        "original_filename": file.filename
    })

@app.post("/api/decrypt")
async def decrypt_file(
    encrypted_file: UploadFile = File(...),
    key_file: UploadFile = File(...)
):
    """Decrypt a PDF file"""
    # 1. Read uploaded files
    encrypted_bytes = await encrypted_file.read()
    key_bytes = await key_file.read()

    # 2. Perform decryption
    decrypted_pdf = decrypt_pdf(encrypted_bytes, key_bytes)

    # 3. Return decrypted file
    return JSONResponse({
        "success": True,
        "decrypted_file": base64.b64encode(decrypted_pdf).decode(),
        "verified": True,
        "filename": "decrypted.pdf"
    })

@app.get("/api/algorithms")
async def get_algorithms():
    """Get available algorithms"""
    return {
        "algorithms": [
            {
                "name": "AES-256-GCM",
                "type": "symmetric",
                "description": "Advanced Encryption Standard with Galois/Counter Mode"
            },
            {
                "name": "ChaCha20-Poly1305",
                "type": "symmetric",
                "description": "ChaCha20 stream cipher with Poly1305 authenticator"
            },
            {
                "name": "RSA-OAEP-4096",
                "type": "asymmetric",
                "description": "RSA with Optimal Asymmetric Encryption Padding"
            }
        ]
    }

@app.get("/api/health")
async def health_check():
    """Health check"""
    return {"status": "healthy", "version": "1.0"}
```

### Step 7: Frontend Integration

**Update services/api.js:**

The API service is already set up! Just need to handle the base64 responses:

```javascript
// In EncryptView.vue
const response = await encryptFile(selectedFile.value)

// Convert base64 to blob and download
const encryptedBlob = base64ToBlob(response.encrypted_file, 'application/pdf')
const keyBlob = base64ToBlob(response.key_file, 'application/json')

downloadFile(encryptedBlob, `encrypted_${response.original_filename}`)
downloadFile(keyBlob, `key_${response.original_filename}.json`)
```

## Implementation Timeline

### Week 1: ✅ COMPLETED
- Frontend setup and implementation
- All UI components
- Routing and navigation
- API service layer
- Documentation

### Week 2: Backend Foundation (CURRENT)
- **Day 1-2**: FastAPI setup, project structure, requirements.txt
- **Day 3-4**: Implement cryptographic algorithms (AES, ChaCha20, RSA)
- **Day 5-7**: Key management and file format implementation

### Week 3: Backend Completion & Integration
- **Day 1-2**: Complete encryption/decryption endpoints
- **Day 3-4**: Integrate frontend with backend (connect API calls)
- **Day 5-6**: Testing encryption/decryption workflow
- **Day 7**: Bug fixes and polish

### Week 4: Testing & Documentation
- **Day 1-2**: Test scenarios (different file sizes, algorithms)
- **Day 3-4**: Security documentation and analysis
- **Day 5-6**: Code documentation and comments
- **Day 7**: Final polish and project presentation prep

## Security Features Implementation

### Features to Implement:

1. **Multi-layer Encryption** ✅ (Design complete)
   - Sequential application of 2 algorithms
   - Random algorithm selection

2. **Authenticated Encryption** ✅ (Design complete)
   - AES-GCM provides authentication
   - ChaCha20-Poly1305 provides authentication
   - HMAC for file integrity

3. **Perfect Forward Secrecy** ✅ (Design complete)
   - Generate new keys for each encryption
   - No key reuse

4. **Secure Random Number Generation** ✅ (Design complete)
   - Use `secrets` module (CSPRNG)
   - For keys, IVs, nonces

5. **Key Encapsulation** ✅ (Design complete)
   - RSA-OAEP for symmetric key encryption
   - 4096-bit keys for quantum resistance

6. **Integrity Verification** ✅ (Design complete)
   - HMAC-SHA256 for tamper detection
   - Authenticated encryption modes

## Testing Strategy

### Unit Tests:
- Test each encryption algorithm independently
- Test key generation functions
- Test file header parsing
- Test HMAC verification

### Integration Tests:
- Full encryption → decryption round-trip
- Test with various PDF sizes
- Test different algorithm combinations

### Security Tests:
- Verify tampering detection (modify ciphertext)
- Test with wrong key file
- Test with corrupted encrypted file

## Success Criteria

### Functional Requirements:
- ✅ Encrypts PDF files successfully
- ✅ Decrypts PDF files correctly
- ✅ Randomly selects 2+ encryption algorithms
- ✅ Generates and exports key files
- ✅ Stores algorithm metadata in encrypted files
- ✅ Verifies file integrity

### Security Requirements:
- ✅ Uses strong, industry-standard algorithms
- ✅ Proper key generation and management
- ✅ Authenticated encryption (prevents tampering)
- ✅ No key reuse (perfect forward secrecy)
- ✅ Secure random number generation

### User Experience Requirements:
- ✅ Clean, intuitive interface (COMPLETED)
- ✅ Clear security information (COMPLETED)
- ⏳ Actual encryption/decryption (Backend pending)
- ⏳ File downloads (Backend pending)

## Next Immediate Steps

1. **Create backend directory structure**
   ```bash
   mkdir -p backend/{crypto,models,utils}
   touch backend/{main.py,requirements.txt,.env.example,config.py}
   touch backend/crypto/{__init__.py,encryption.py,decryption.py,key_management.py,algorithms.py,utils.py}
   touch backend/models/{__init__.py,schemas.py}
   touch backend/utils/{__init__.py,file_handler.py}
   ```

2. **Set up Python virtual environment**
   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Start implementing crypto/algorithms.py**
   - Begin with AES-256-GCM implementation
   - Add ChaCha20-Poly1305
   - Implement RSA key generation
   - Add HMAC functions

4. **Implement main.py FastAPI app**
   - Basic app setup with CORS
   - Health check endpoint
   - File upload handling

5. **Test backend independently**
   - Use Postman or curl to test endpoints
   - Verify encryption/decryption works

6. **Connect frontend to backend**
   - Uncomment API calls in Vue components
   - Test full workflow

## Documentation Requirements

### Code Documentation:
- Inline comments explaining cryptographic operations
- Docstrings for all functions
- Security considerations noted

### Academic Documentation:
- Explanation of Kerckhoffs's Principle
- Hybrid encryption rationale
- Algorithm selection justification
- Security analysis and threat model

### User Documentation:
- How to run the application
- How to use encryption/decryption
- Security best practices

---

## Project Status Summary

**Current Status**: 🚧 **Frontend Complete | Backend Implementation Phase**

**Completed**:
- ✅ Full frontend implementation with polished UI
- ✅ Vue 3 + TailwindCSS + Vue Router
- ✅ Drag & drop file uploads
- ✅ Security indicators and educational content
- ✅ API service layer ready
- ✅ Comprehensive documentation

**In Progress**:
- ⏳ Backend implementation (FastAPI + Cryptography)

**Next Milestones**:
1. Backend project setup
2. Cryptographic core implementation
3. API endpoints implementation
4. Frontend-backend integration
5. Testing and security validation

**Last Updated**: October 2025
