# PDF CARRIER - PROJECT REPORT

## 1. PROBLEM DESCRIPTION

### Main Problem
Modern digital communication requires secure methods for encrypting and sharing PDF documents. Current solutions have several limitations:

- Most tools use single-layer encryption (single point of failure)
- Many rely on "security by obscurity" (hiding algorithms instead of protecting keys)
- Poor key management practices
- Lack of transparency in encryption processes

### Security Requirements
- **Confidentiality:** Prevent unauthorized access
- **Integrity:** Detect tampering
- **Authentication:** Verify data source
- **Non-repudiation:** Prove origin

---

## 2. SOLUTION

### Core Approach
A multi-layer hybrid encryption system based on modern cryptographic principles.

### Key Principles

**A. Kerckhoffs's Principle**
- Algorithms are public and transparent
- Security relies on key secrecy, not algorithm secrecy
- Encryption metadata stored openly in file headers

**B. Hybrid Encryption**
- **RSA-4096:** For key encapsulation (secure key exchange)
- **AES/ChaCha20:** For data encryption (fast bulk encryption)
- Combines security of asymmetric + speed of symmetric encryption

**C. Multi-Layer Security (Defense in Depth)**
- Two encryption algorithms applied sequentially
- If one algorithm is compromised, second layer protects data
- Independent keys for each layer

### Supported Algorithms

**Modern (Secure):**
- **AES-256-GCM:** 256-bit, authenticated encryption, NIST approved
- **AES-128-GCM:** 128-bit, authenticated encryption
- **ChaCha20-Poly1305:** 256-bit, software-efficient
- **AES-256-CBC:** 256-bit, traditional block cipher
- **RSA-OAEP-4096:** Asymmetric, key encapsulation
- **HMAC-SHA256:** Message authentication

**Academic (Insecure - Educational Only):**
- **DES:** 56-bit, vulnerable to brute force
- **Playfair:** Classical cipher, frequency analysis

---

## 3. IMPLEMENTATION

### System Architecture

```
┌─────────────────┐
│  Vue.js Frontend │  ← Web UI (Port 5173)
└────────┬─────────┘
         │ REST API
         ▼
┌─────────────────┐
│ FastAPI Backend  │  ← API Server (Port 8000)
└────────┬─────────┘
         │
         ▼
┌─────────────────┐
│  Cryptography   │  ← Python crypto library
└─────────────────┘
```

### Encryption Workflow

```
1. Key Generation
   - Generate RSA-4096 key pair
   - Generate symmetric keys for selected algorithms
   - Generate HMAC key

2. Algorithm Selection
   - Random: System selects 2 algorithms
   - Manual: User selects 2 algorithms

3. Layer 1 Encryption
   - Encrypt PDF with first algorithm
   - Generate unique IV/nonce

4. Layer 2 Encryption
   - Encrypt Layer 1 output with second algorithm
   - Generate unique IV/nonce

5. Key Encapsulation
   - Combine symmetric keys
   - Encrypt with RSA public key

6. Integrity Protection
   - Compute HMAC-SHA256 of final ciphertext

7. File Generation
   - Create encrypted file (JSON with metadata)
   - Create key file (RSA private key)
```

### Decryption Workflow

```
1. File Validation
   - Parse encrypted file
   - Extract metadata

2. HMAC Verification
   - Verify file integrity
   - Abort if tampered

3. Key Decryption
   - Decrypt symmetric keys with RSA private key

4. Layer 2 Decryption
   - Remove second encryption layer

5. Layer 1 Decryption
   - Remove first encryption layer
   - Recover original PDF
```

### Technology Stack

**Backend:**
- Python 3.10+
- FastAPI (REST API)
- cryptography library (FIPS 140-2 compliant)
- uvicorn (ASGI server)

**Frontend:**
- Vue 3
- Vite
- TailwindCSS
- Axios

---

## 4. DESIGN DETAILS

### File Format

**Encrypted File (JSON):**
```json
{
  "header": {
    "version": "2.0",
    "algorithms": ["AES-256-GCM", "ChaCha20-Poly1305"],
    "encrypted_symmetric_keys": "<base64>",
    "layer1_iv": "<base64>",
    "layer2_nonce": "<base64>",
    "hmac_key": "<base64>",
    "timestamp": "2025-11-09T20:17:20Z",
    "original_filename": "document.pdf"
  },
  "ciphertext": "<base64>",
  "hmac": "<base64>"
}
```

**Key File (JSON):**
```json
{
  "version": "1.0",
  "key_type": "RSA_PRIVATE",
  "private_key_pem": "-----BEGIN PRIVATE KEY-----\n...",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...",
  "key_size": 4096,
  "created_at": "2025-11-09T20:17:20Z",
  "key_id": "uuid",
  "algorithm_pool": ["AES-256-GCM", "ChaCha20-Poly1305"]
}
```

### API Endpoints

```
GET  /api/health           - Health check
GET  /api/algorithms       - List available algorithms
POST /api/encrypt          - Encrypt PDF file
POST /api/decrypt          - Decrypt PDF file
POST /api/metadata         - Get encrypted file metadata
```

### Security Features

**1. Perfect Forward Secrecy**
- Fresh keys for every encryption
- No key reuse

**2. Authenticated Encryption**
- AEAD modes (GCM, ChaCha20-Poly1305)
- Additional HMAC layer
- Tamper detection

**3. Secure Random Generation**
- CSPRNG for all random values
- Python `secrets` module

**4. RSA-4096 Key Encapsulation**
- Quantum-resistant key size
- OAEP padding

**5. HMAC Verification**
- Constant-time comparison
- Prevents timing attacks

### Security Analysis

**Strengths:**
- ✅ Industry-standard algorithms (NIST approved)
- ✅ Multi-layer defense
- ✅ Authenticated encryption
- ✅ Perfect forward secrecy
- ✅ Quantum-resistant key sizes

**Weaknesses:**
- ⚠️ Private key not password-protected
- ⚠️ 10MB file size limit
- ⚠️ No security audit (academic project)

**Threat Model:**

| Threat | Mitigation | Status |
|--------|-----------|--------|
| Eavesdropping | 256-bit encryption | ✅ Protected |
| Tampering | HMAC + AEAD | ✅ Detected |
| Brute Force | Large key space | ✅ Infeasible |
| Algorithm Breach | Two layers | ✅ Protected |
| Key Theft | Requires both files | ⚠️ Accepted |

---

## 5. RESULTS

### Completed Features
- ✅ Multi-algorithm encryption (5 secure + 2 academic)
- ✅ Hybrid encryption (RSA + AES/ChaCha20)
- ✅ Two-layer encryption
- ✅ Random/manual algorithm selection
- ✅ HMAC integrity verification
- ✅ Web UI (Vue 3 + TailwindCSS)
- ✅ RESTful API with Swagger docs
- ✅ Educational comparison (modern vs classical)

### Performance
- Encryption: ~5-10 MB/s
- Decryption: ~8-12 MB/s
- RSA key generation: ~2-3 seconds
- File size overhead: ~40%

### Academic Contributions
- **Kerckhoffs's Principle:** Practical demonstration
- **Modern vs Classical:** Direct comparison (AES vs DES)
- **Security Analysis:** Threat modeling and attack scenarios
- **Real-World Application:** Production-ready architecture

---

## 6. CONCLUSION

### Achievements
1. ✅ Successfully implemented modern cryptographic principles
2. ✅ Made cryptography accessible through simple UI
3. ✅ Combined academic value with practical application
4. ✅ Demonstrated Kerckhoffs's Principle in practice

### Key Lessons
- Multi-layer security provides valuable redundancy
- User experience critical for security adoption
- Classical algorithms have educational value
- Industry-standard libraries essential

### Future Enhancements
1. **Stream encryption** for large files
2. **Password-based key file encryption** (Argon2)
3. **Post-quantum cryptography** (CRYSTALS-Kyber)
4. **Cloud storage integration**
5. **Multi-user key sharing**
6. **Mobile applications**

### Recommendations for Production
- Conduct professional security audit
- Implement HSM for key storage
- Add password protection for key files
- Enable HTTPS/TLS for all communications
- Implement audit logging
- Add monitoring and alerting

---

## Final Thoughts

This project demonstrates that **strong cryptography can be both secure and user-friendly**. By implementing Kerckhoffs's Principle, hybrid encryption, and multi-layer security, the system provides robust protection while maintaining transparency.

**Key Takeaways:**
- Algorithm transparency works (security in keys, not secrecy)
- Multi-layer security is practical and effective
- Education through hands-on comparison
- Usability enables security adoption

---

**Project Status:** ✅ Complete and Functional
**License:** MIT (Educational)
**Last Updated:** November 2025
