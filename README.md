# PDF Carrier

A secure file encryption system for PDF files, demonstrating advanced cryptographic concepts including hybrid encryption, multi-layer security, and proper key management.

## Project Overview

This project implements a secure PDF encryption/decryption system that combines:
- **Hybrid Encryption**: RSA + AES-256-GCM + ChaCha20-Poly1305
- **Multi-layer Security**: Multiple encryption algorithms applied sequentially
- **Proper Key Management**: Secure key generation and distribution
- **Kerckhoffs's Principle**: Algorithm transparency with key secrecy

## Features

### Security Features
- ✅ Multi-layer encryption (2+ algorithms)
- ✅ Authenticated encryption (prevents tampering)
- ✅ Perfect forward secrecy (no key reuse)
- ✅ Secure random key generation
- ✅ HMAC integrity verification
- ✅ RSA-4096 key encapsulation

### User Features
- ✅ Beautiful, polished web interface
- ✅ Drag & drop file upload
- ✅ Real-time encryption/decryption progress
- ✅ Automatic key generation
- ✅ Random algorithm selection
- ✅ Downloadable key files
- ✅ Security indicators and educational content

## Architecture

```
┌──────────────────┐
│   Vue.js SPA     │  ← Beautiful frontend with TailwindCSS
│   (Frontend)     │
└────────┬─────────┘
         │ REST API
         ▼
┌──────────────────┐
│  FastAPI Server  │  ← Backend API (TO BE IMPLEMENTED)
│   (Backend)      │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Cryptography    │  ← Python cryptography library
│    Library       │
└──────────────────┘
```

## Project Structure

```
pdf-carrier/
├── frontend/              # Vue.js frontend (✅ COMPLETED)
│   ├── src/
│   │   ├── components/   # Reusable Vue components
│   │   ├── views/        # Page components
│   │   ├── router/       # Vue Router
│   │   ├── services/     # API integration
│   │   └── ...
│   ├── package.json
│   └── README.md
├── backend/              # FastAPI backend (⏳ TO BE IMPLEMENTED)
│   ├── main.py
│   ├── crypto/
│   ├── models/
│   └── requirements.txt
├── IMPLEMENTATION_PLAN.md  # Detailed implementation guide
└── README.md
```

## Current Status

### ✅ Phase 1: Frontend (COMPLETED)
- [x] Vue 3 project setup with Vite
- [x] TailwindCSS configuration
- [x] Vue Router setup
- [x] Main App layout with navigation
- [x] FileUpload component
- [x] SecurityIndicator component
- [x] EncryptView page
- [x] DecryptView page
- [x] API service layer
- [x] Responsive design
- [x] Animations and polish

### ⏳ Phase 2: Backend (PENDING)
- [ ] FastAPI project setup
- [ ] Cryptographic core implementation
- [ ] Key management system
- [ ] Encryption endpoint
- [ ] Decryption endpoint
- [ ] Security features implementation

## Quick Start

### Frontend Development

The frontend is fully implemented and ready to use!

```bash
cd frontend
npm install
npm run dev
```

Visit: **http://localhost:5173/**

See [frontend/README.md](frontend/README.md) for more details.

### Backend Development (Coming Soon)

The backend implementation will follow the detailed plan in [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md).

## Documentation

- **[IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md)** - Comprehensive implementation guide
- **[frontend/README.md](frontend/README.md)** - Frontend documentation
- **backend/README.md** - Backend documentation (coming soon)

## Technologies Used

### Frontend
- Vue 3 (Composition API)
- Vite
- Vue Router
- TailwindCSS
- Axios

### Backend (Planned)
- Python 3.10+
- FastAPI
- cryptography library
- PyPDF2
- uvicorn

### Cryptographic Algorithms
- **AES-256-GCM**: Symmetric encryption with authentication
- **ChaCha20-Poly1305**: Alternative symmetric encryption
- **RSA-OAEP (4096-bit)**: Asymmetric key encapsulation
- **HMAC-SHA256**: Message authentication
- **Argon2id**: Key derivation (planned)

## How It Works

### Encryption Process
1. User uploads a PDF file
2. System generates secure random keys
3. Randomly selects 2+ encryption algorithms
4. Applies encryption layers sequentially
5. Encapsulates keys with RSA
6. Creates encrypted file with metadata header
7. Generates downloadable key file

### Decryption Process
1. User uploads encrypted PDF and key file
2. System reads metadata header
3. Loads private key
4. Verifies file integrity (HMAC)
5. Decrypts symmetric keys with RSA
6. Removes encryption layers in reverse order
7. Restores original PDF

## Security Concepts Demonstrated

### 1. Kerckhoffs's Principle
- Encryption algorithms are NOT secret
- Only the key is secret
- Algorithm metadata is stored in file header
- Security relies on key strength, not algorithm obscurity

### 2. Hybrid Encryption
- RSA for key encapsulation (slow but secure)
- Symmetric algorithms for data (fast and efficient)
- Combines best of both worlds

### 3. Defense in Depth
- Multiple encryption layers
- Even if one algorithm is broken, others protect the data
- Authenticated encryption prevents tampering

### 4. Perfect Forward Secrecy
- Fresh keys generated for each encryption
- No key reuse
- Past sessions remain secure even if key is compromised

## Academic Context

This project was developed for a Cryptography course to demonstrate:
- Understanding of modern encryption algorithms
- Proper key management practices
- Real-world security system design
- Kerckhoffs's Principle in action
- Hybrid encryption architecture
- Multi-layer security approach

## Next Steps

1. **Implement Backend** following [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md)
2. **Integrate Frontend & Backend** - Connect API calls
3. **Add Test Scenarios** - Security testing and validation
4. **Documentation** - Complete technical documentation
5. **Deployment** - Prepare for local deployment

## Development Timeline

- **Week 1**: ✅ Frontend development (COMPLETED)
- **Week 2**: Backend foundation
- **Week 3**: Backend completion & integration
- **Week 4**: Testing, documentation, polish

## Contributing

This is an academic project. If you're using this as reference:
1. Understand the cryptographic concepts
2. Read the [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md)
3. Follow security best practices
4. Never roll your own crypto in production!

## License

MIT

---

**⚠️ Important Security Note:**

This is an educational project demonstrating cryptographic concepts. While it uses industry-standard libraries and follows best practices, it should not be used for production security-critical applications without thorough security audit and testing.

For production use, consider established solutions like:
- GNU Privacy Guard (GPG)
- OpenSSL
- AWS KMS
- Azure Key Vault

---

Built with ❤️ for Cryptography Course Project

**Project Status**: ✅ **COMPLETE - Ready to Use!**

**Last Updated**: October 2025

---

## 🚀 Quick Start

See [QUICKSTART.md](QUICKSTART.md) for detailed instructions.

**TL;DR:**

1. Start Backend: `cd backend && source venv/bin/activate && python main.py`
2. Start Frontend: `cd frontend && npm run dev`
3. Visit: http://localhost:5173
