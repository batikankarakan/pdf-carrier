# PDF Carrier - Quick Start Guide

Complete guide to running the PDF encryption/decryption system.

## 🚀 Quick Start (3 Steps)

### Step 1: Start the Backend

```bash
cd backend
source venv/bin/activate  # On Windows: venv\Scripts\activate
python main.py
```

**Backend will run on:** http://localhost:8000

### Step 2: Start the Frontend

Open a **new terminal** window:

```bash
cd frontend
npm run dev
```

**Frontend will run on:** http://localhost:5173

### Step 3: Use the Application

Open your browser and visit: **http://localhost:5173**

---

## 📋 First Time Setup

### Backend Setup

```bash
# Navigate to backend directory
cd backend

# Create Python virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Frontend Setup

```bash
# Navigate to frontend directory
cd frontend

# Install dependencies
npm install
```

---

## 💡 How to Use

### Generate a Test PDF (Optional)

Need a test file? Generate one:

```bash
python create_test_pdf.py
```

This creates `test_document.pdf` with project information and encryption details.

### Encrypt a PDF File

1. Go to the **Encrypt** page
2. **Drag & drop** or click to select a PDF file (use `test_document.pdf` or any PDF)
3. Click **"Encrypt File Now"**
4. Wait for encryption to complete
5. **Download** two files:
   - **Encrypted PDF** (`.encrypted` file)
   - **Key File** (`.key` file)
6. **⚠️ Important**: Keep the key file safe! You need it to decrypt.

### Decrypt a PDF File

1. Go to the **Decrypt** page
2. Upload the **encrypted PDF file**
3. Upload the **key file**
4. Click **"Decrypt File Now"**
5. Wait for decryption to complete
6. **Download** the decrypted PDF

---

## 🔧 Troubleshooting

### Backend Issues

**Problem:** `ModuleNotFoundError`
```bash
# Solution: Make sure virtual environment is activated
source venv/bin/activate
pip install -r requirements.txt
```

**Problem:** Port 8000 already in use
```bash
# Solution: Kill the process or use different port
python main.py  # Will run on port 8000
# OR
uvicorn main:app --port 8001
```

### Frontend Issues

**Problem:** Port 5173 already in use
```bash
# Solution: Vite will automatically try another port
# Just use the port shown in the terminal
```

**Problem:** `npm: command not found`
```bash
# Solution: Install Node.js
# Visit: https://nodejs.org/
```

**Problem:** TailwindCSS not working
```bash
# Solution: Reinstall dependencies
rm -rf node_modules package-lock.json
npm install
```

### Connection Issues

**Problem:** Frontend can't connect to backend
- Make sure backend is running (http://localhost:8000)
- Check browser console for errors
- Verify CORS settings in backend/main.py

**Problem:** "Network Error" when encrypting/decrypting
- Make sure both frontend AND backend are running
- Check that backend shows "Uvicorn running on http://0.0.0.0:8000"

---

## 📡 API Endpoints

All endpoints are available at `http://localhost:8000`

### Health Check
```bash
curl http://localhost:8000/api/health
```

### Get Algorithms
```bash
curl http://localhost:8000/api/algorithms
```

### Encrypt File
```bash
curl -X POST "http://localhost:8000/api/encrypt" \
  -F "file=@document.pdf"
```

### Decrypt File
```bash
curl -X POST "http://localhost:8000/api/decrypt" \
  -F "encrypted_file=@encrypted.pdf.encrypted" \
  -F "key_file=@key.key"
```

### API Documentation
Visit: **http://localhost:8000/docs** (Swagger UI)

---

## 🧪 Testing the System

### Test Encryption/Decryption Cycle

1. **Create a test PDF** (any PDF file will work)

2. **Encrypt it:**
   - Upload to Encrypt page
   - Download encrypted file and key

3. **Decrypt it:**
   - Upload encrypted file + key to Decrypt page
   - Download decrypted PDF

4. **Verify:**
   - Compare original PDF with decrypted PDF
   - They should be identical

### Test Different Scenarios

**Scenario 1: Wrong Key File**
- Try decrypting with a different key file
- Should fail with error message

**Scenario 2: Corrupted File**
- Modify the encrypted file in a text editor
- Try to decrypt
- Should fail HMAC verification

**Scenario 3: Multiple Encryptions**
- Encrypt same file multiple times
- Each encryption should produce different ciphertext
- Demonstrates perfect forward secrecy

---

## 📁 Project Structure

```
pdf-carrier/
├── frontend/                # Vue.js frontend
│   ├── src/
│   │   ├── components/     # Reusable components
│   │   ├── views/          # Pages
│   │   ├── router/         # Routing
│   │   └── services/       # API calls
│   └── package.json
│
├── backend/                 # FastAPI backend
│   ├── crypto/             # Cryptographic modules
│   │   ├── algorithms.py   # AES, ChaCha20, RSA, HMAC
│   │   ├── encryption.py   # Encryption workflow
│   │   ├── decryption.py   # Decryption workflow
│   │   └── key_management.py
│   ├── main.py             # FastAPI app
│   └── requirements.txt
│
├── IMPLEMENTATION_PLAN.md  # Detailed technical plan
├── QUICKSTART.md           # This file
└── README.md               # Project overview
```

---

## 🔐 Security Features

The system demonstrates:

- ✅ **Hybrid Encryption**: RSA-4096 + AES-256-GCM + ChaCha20-Poly1305
- ✅ **Multi-layer Security**: Defense in depth with 2 encryption algorithms
- ✅ **Authenticated Encryption**: Prevents tampering
- ✅ **Perfect Forward Secrecy**: Unique keys for each encryption
- ✅ **HMAC Verification**: Detects file modification
- ✅ **Kerckhoffs's Principle**: Algorithm metadata in file header

---

## 🎓 For Academic Presentation

### Key Points to Highlight:

1. **Kerckhoffs's Principle**
   - Algorithm selection is stored in plaintext (file header)
   - Security relies on key secrecy, not algorithm secrecy
   - Demonstrates understanding of modern cryptography principles

2. **Hybrid Encryption**
   - RSA for key encapsulation (secure but slow)
   - AES/ChaCha20 for data encryption (fast)
   - Best of both worlds

3. **Defense in Depth**
   - Multiple encryption layers
   - Even if one algorithm is compromised, data remains protected

4. **Real-World Practices**
   - Uses industry-standard libraries
   - Follows NIST recommendations
   - Similar to TLS, PGP, and other production systems

---

## 🛑 Common Mistakes to Avoid

1. **❌ Not activating virtual environment**
   - Always run `source venv/bin/activate` before starting backend

2. **❌ Forgetting to save key file**
   - Key file is required for decryption
   - Cannot be recovered if lost

3. **❌ Running only frontend or only backend**
   - Both must be running for the system to work

4. **❌ Using wrong file extensions**
   - Encrypted files should have `.encrypted` extension
   - Key files should have `.key` extension

---

## 📞 Support

If you encounter issues:

1. Check this QUICKSTART guide
2. Read [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) for technical details
3. Check browser console for errors (F12)
4. Check backend terminal for error messages

---

## ✅ Checklist Before Demo

- [ ] Backend is running (http://localhost:8000)
- [ ] Frontend is running (http://localhost:5173)
- [ ] Test PDF file ready
- [ ] Encryption works (can download files)
- [ ] Decryption works (can restore original)
- [ ] Know how to explain Kerckhoffs's Principle
- [ ] Understand why algorithm metadata is in header
- [ ] Can explain hybrid encryption benefits

---

**Project Status**: ✅ **Complete and Ready to Use**

**Last Updated**: October 2025
