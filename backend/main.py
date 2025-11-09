"""
PDF Carrier - FastAPI Backend

Secure PDF encryption/decryption system demonstrating:
- Hybrid encryption (RSA + AES + ChaCha20)
- Multi-layer security (defense in depth)
- Proper key management
- Kerckhoffs's Principle (algorithm transparency)
"""

from fastapi import FastAPI, UploadFile, File, HTTPException, Form
from fastapi.responses import JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
import base64
from typing import Annotated, Dict
from pydantic import BaseModel

from crypto.encryption import encrypt_pdf, get_encryption_info, AVAILABLE_ALGORITHMS
from crypto.decryption import decrypt_pdf, parse_encrypted_file_metadata
from crypto import classic_ciphers


# Initialize FastAPI app
app = FastAPI(
    title="PDF Carrier API",
    description="Secure PDF encryption/decryption system for cryptography course project",
    version="1.0.0"
)

# Configure CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:5174"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# Pydantic Modelleri (Playfair için)
# =============================================================================

class PlayfairRequest(BaseModel):
    text: str
    key: str

class PlayfairResponse(BaseModel):
    text: str
    key: str
    result: str


@app.get("/api/health")
async def health_check() -> Dict:
    """
    Health check endpoint

    Returns:
        Status and version information
    """
    return {
        "status": "healthy",
        "version": "1.0.0",
        "service": "PDF Carrier API"
    }


@app.get("/api/algorithms")
async def get_algorithms() -> Dict:
    """
    Get available encryption algorithms

    Returns information about all supported encryption algorithms.
    This demonstrates Kerckhoffs's Principle - the algorithms are NOT secret.
    """
    return {
        "algorithms": [
            {
                "name": "AES-256-GCM",
                "type": "symmetric",
                "key_size": "256 bits",
                "description": "Advanced Encryption Standard with Galois/Counter Mode",
                "features": ["Authenticated encryption", "Hardware accelerated", "NIST approved"],
                "security": "high"
            },
            {
                "name": "AES-128-GCM",
                "type": "symmetric",
                "key_size": "128 bits",
                "description": "Advanced Encryption Standard with Galois/Counter Mode (128-bit)",
                "features": ["Authenticated encryption", "Hardware accelerated", "NIST approved"],
                "security": "high"
            },
            {
                "name": "ChaCha20-Poly1305",
                "type": "symmetric",
                "key_size": "256 bits",
                "description": "ChaCha20 stream cipher with Poly1305 authenticator",
                "features": ["Authenticated encryption", "Software efficient", "Modern design"],
                "security": "high"
            },
            {
                "name": "AES-256-CBC",
                "type": "symmetric",
                "key_size": "256 bits",
                "description": "Advanced Encryption Standard with Cipher Block Chaining",
                "features": ["Block cipher mode", "HMAC for authentication", "Traditional mode"],
                "security": "high"
            },
            {
                "name": "DES",
                "type": "symmetric",
                "key_size": "56 bits (8 bytes with parity)",
                "description": "Data Encryption Standard (Historic - INSECURE)",
                "features": ["Academic purposes only", "Vulnerable to brute force", "Deprecated"],
                "security": "low",
                "warning": "⚠️ INSECURE - For educational/academic purposes only. Vulnerable to brute force attacks."
            },
            {
                "name": "RSA-OAEP-4096",
                "type": "asymmetric",
                "key_size": "4096 bits",
                "description": "RSA with Optimal Asymmetric Encryption Padding",
                "features": ["Key encapsulation", "Quantum resistant", "Hybrid encryption"],
                "security": "high"
            },
            {
                "name": "HMAC-SHA256",
                "type": "mac",
                "output_size": "256 bits",
                "description": "Hash-based Message Authentication Code",
                "features": ["Integrity verification", "Tamper detection"],
                "security": "high"
            }
        ],
        "selection_method": "Random selection of 2 algorithms",
        "security_principle": "Kerckhoffs's Principle - algorithm choice is public, only key is secret"
    }


@app.post("/api/encrypt")
async def encrypt_file(
    file: UploadFile = File(...),
    algorithms: str = Form(None)
) -> JSONResponse:
    """
    Encrypt a PDF file

    Process:
    1. Validate file type (PDF)
    2. Generate encryption keys
    3. Use provided algorithms or randomly select 2 algorithms
    4. Apply multi-layer encryption
    5. Create encrypted file with metadata
    6. Generate key file

    Args:
        file: PDF file to encrypt
        algorithms: Optional JSON string array of algorithm names to use

    Returns:
        JSON response with:
        - success: bool
        - algorithms: List of algorithms used
        - encrypted_file: Base64-encoded encrypted file
        - key_file: Base64-encoded key file
        - timestamp: Encryption timestamp
        - original_filename: Original file name

    Raises:
        HTTPException: If file is invalid or encryption fails
    """
    # Validate file type
    if not file.filename.lower().endswith('.pdf'):
        raise HTTPException(
            status_code=400,
            detail="Only PDF files are supported"
        )

    try:
        # Read uploaded file
        pdf_bytes = await file.read()

        # Parse algorithms if provided
        selected_algorithms = None
        if algorithms:
            import json
            try:
                selected_algorithms = json.loads(algorithms)
                # Validate that we have exactly 2 algorithms
                if not isinstance(selected_algorithms, list) or len(selected_algorithms) != 2:
                    raise HTTPException(
                        status_code=400,
                        detail="Must provide exactly 2 algorithms"
                    )
                # Validate that algorithms are in the available list
                if not all(algo in AVAILABLE_ALGORITHMS for algo in selected_algorithms):
                    raise HTTPException(
                        status_code=400,
                        detail=f"Invalid algorithms. Available: {AVAILABLE_ALGORITHMS}"
                    )
            except json.JSONDecodeError:
                raise HTTPException(
                    status_code=400,
                    detail="Invalid algorithms format. Must be JSON array."
                )

        # Validate file size (max 10MB)
        max_size = 10 * 1024 * 1024  # 10MB
        if len(pdf_bytes) > max_size:
            raise HTTPException(
                status_code=400,
                detail=f"File too large. Maximum size is {max_size / (1024*1024)}MB"
            )

        # Perform encryption
        encrypted_file_bytes, key_file_bytes = encrypt_pdf(pdf_bytes, file.filename, selected_algorithms)

        # Parse the encrypted file to get metadata
        encrypted_file_json = encrypted_file_bytes.decode('utf-8')
        import json
        encrypted_data = json.loads(encrypted_file_json)

        # Prepare response
        response_data = {
            "success": True,
            "algorithms": encrypted_data['header']['algorithms'],
            "encrypted_file": base64.b64encode(encrypted_file_bytes).decode('utf-8'),
            "key_file": base64.b64encode(key_file_bytes).decode('utf-8'),
            "timestamp": encrypted_data['header']['timestamp'],
            "original_filename": file.filename,
            "encryption_info": get_encryption_info(len(pdf_bytes))
        }

        return JSONResponse(content=response_data)

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Encryption failed: {str(e)}"
        )


@app.post("/api/decrypt")
async def decrypt_file(
    encrypted_file: UploadFile = File(...),
    key_file: UploadFile = File(...)
) -> JSONResponse:
    """
    Decrypt an encrypted PDF file

    Process:
    1. Validate uploaded files
    2. Load key file
    3. Parse encrypted file metadata
    4. Verify HMAC (integrity check)
    5. Decrypt symmetric keys with RSA
    6. Remove encryption layers
    7. Return original PDF

    Args:
        encrypted_file: Encrypted PDF file
        key_file: Key file (JSON)

    Returns:
        JSON response with:
        - success: bool
        - decrypted_file: Base64-encoded decrypted PDF
        - verified: bool (integrity check result)
        - filename: Original filename
        - metadata: Encryption metadata

    Raises:
        HTTPException: If decryption fails or files are invalid
    """
    try:
        # Read uploaded files
        encrypted_bytes = await encrypted_file.read()
        key_bytes = await key_file.read()

        # Perform decryption
        decrypted_pdf_bytes, metadata = decrypt_pdf(encrypted_bytes, key_bytes)

        # Prepare response
        response_data = {
            "success": True,
            "decrypted_file": base64.b64encode(decrypted_pdf_bytes).decode('utf-8'),
            "verified": metadata['verified'],
            "filename": metadata['original_filename'],
            "metadata": {
                "algorithms_used": metadata['algorithms_used'],
                "timestamp": metadata['timestamp'],
                "integrity_check": metadata['integrity_check']
            }
        }

        return JSONResponse(content=response_data)

    except ValueError as e:
        # Client error (wrong key, tampered file, etc.)
        raise HTTPException(
            status_code=400,
            detail=str(e)
        )
    except Exception as e:
        # Server error
        raise HTTPException(
            status_code=500,
            detail=f"Decryption failed: {str(e)}"
        )


@app.post("/api/metadata")
async def get_encrypted_file_metadata(file: UploadFile = File(...)) -> JSONResponse:
    """
    Get metadata from an encrypted file without decrypting

    Useful for displaying information before decryption.

    Args:
        file: Encrypted file

    Returns:
        JSON with file metadata

    Raises:
        HTTPException: If file is invalid
    """
    try:
        file_bytes = await file.read()
        metadata = parse_encrypted_file_metadata(file_bytes)

        return JSONResponse(content={
            "success": True,
            "metadata": metadata
        })

    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail=str(e)
        )


# Root endpoint
@app.get("/")
async def root():
    """
    Root endpoint with API information
    """
    return {
        "service": "PDF Carrier API",
        "version": "1.0.0",
        "description": "Secure PDF encryption/decryption system",
        "endpoints": {
            "health": "/api/health",
            "algorithms": "/api/algorithms",
            "encrypt": "/api/encrypt (POST)",
            "decrypt": "/api/decrypt (POST)",
            "metadata": "/api/metadata (POST)"
        },
        "security_features": [
            "Hybrid encryption (RSA + AES + ChaCha20)",
            "Multi-layer security",
            "Authenticated encryption",
            "Perfect forward secrecy",
            "HMAC integrity verification"
        ],
        "documentation": "/docs"
    }

    # =============================================================================
#
# KLASİK ALGORİTMA ENDPOINT'LERİ (AKADEMİK AMAÇLI)
#
# =============================================================================

@app.post("/api/v1/encrypt/playfair", response_model=PlayfairResponse, tags=["Classic Ciphers (Insecure)"])
async def api_encrypt_playfair(request: PlayfairRequest):
    """
    JSON olarak gelen metni Playfair ile şifreler.
    UYARI: Güvensiz, sadece akademik amaçlı.
    """
    try:
        ciphertext = classic_ciphers.encrypt_playfair(request.text, request.key)
        return PlayfairResponse(
            text=request.text,
            key=request.key,
            result=ciphertext
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Playfair şifreleme hatası: {e}")

@app.post("/api/v1/decrypt/playfair", response_model=PlayfairResponse, tags=["Classic Ciphers (Insecure)"])
async def api_decrypt_playfair(request: PlayfairRequest):
    """
    JSON olarak gelen metni Playfair ile deşifre eder.
    UYARI: Güvensiz, sadece akademik amaçlı.
    """
    try:
        plaintext = classic_ciphers.decrypt_playfair(request.text, request.key)
        return PlayfairResponse(
            text=request.text,
            key=request.key,
            result=plaintext
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Playfair deşifre hatası: {e}")

# --- DES Endpointleri (Dosya Yükleme) ---

@app.post("/api/v1/encrypt/des", tags=["Classic Ciphers (Insecure)"])
async def api_encrypt_des(
    key: Annotated[str, Form()],
    file: UploadFile = File(...)
):
    """
    Yüklenen dosyayı (PDF vb.) DES ile şifreler.
    UYARI: Güvensiz, sadece akademik amaçlı.
    """
    if not file:
        raise HTTPException(status_code=400, detail="Dosya yüklenmedi")
        
    try:
        # Anahtarı string'den bytes'a çevir (UTF-8)
        key_bytes = key.encode('utf-8')
        
        # Dosya içeriğini oku
        file_data = await file.read()
        
        # DES ile şifrele
        encrypted_data = classic_ciphers.encrypt_des(file_data, key_bytes)
        
        # Şifrelenmiş dosyayı kullanıcıya döndür
        return Response(
            content=encrypted_data,
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f"attachment; filename=encrypted_{file.filename}.des"
            }
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DES şifreleme hatası: {e}")

@app.post("/api/v1/decrypt/des", tags=["Classic Ciphers (Insecure)"])
async def api_decrypt_des(
    key: Annotated[str, Form()],
    file: UploadFile = File(...)
):
    """
    DES ile şifrelenmiş dosyayı (.des) deşifre eder.
    UYARI: Güvensiz, sadece akademik amaçlı.
    """
    if not file:
        raise HTTPException(status_code=400, detail="Dosya yüklenmedi")
        
    try:
        # Anahtarı string'den bytes'a çevir (UTF-8)
        key_bytes = key.encode('utf-8')
        
        # Şifreli dosya içeriğini oku
        file_data = await file.read()
        
        # DES ile deşifre et
        decrypted_data = classic_ciphers.decrypt_des(file_data, key_bytes)
        
        # Orijinal dosya adını tahmin etmeye çalış (sondaki .des'i kaldır)
        original_filename = file.filename.removesuffix(".des") if file.filename.endswith(".des") else f"decrypted_{file.filename}"
        
        # Deşifre edilmiş dosyayı döndür
        return Response(
            content=decrypted_data,
            media_type="application/octet-stream", # Orijinal MIME tipini bilemeyiz, bu en güvenlisi
            headers={
                "Content-Disposition": f"attachment; filename={original_filename}"
            }
        )
        
    except Exception as e:
        # Sık karşılaşılan bir hata: Yanlış anahtar veya bozuk dosya
        if "padding" in str(e).lower() or "ValueError" in str(e):
             raise HTTPException(status_code=400, detail="Deşifre hatası: Anahtar yanlış veya dosya bozuk.")
        raise HTTPException(status_code=500, detail=f"DES deşifre hatası: {e}")

# ... (Mevcut if __name__ == "__main__": bloğunuz burada olmalı)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
