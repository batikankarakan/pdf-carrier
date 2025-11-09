# backend/crypto/classic_ciphers.py

"""
Klasik ve Akademik Kripto Algoritmaları
--------------------------------------

UYARI: Bu dosyada bulunan algoritmalar (DES, Playfair) GÜVENSİZDİR.
Modern kriptografide KESİNLİKLE kullanılmamalıdır.
Bunlar sadece "PDF Carrier" projesinin akademik ve tarihsel 
konseptleri gösterme amacıyla eklenmiştir.
"""

import os
import re
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# =============================================================================
#
# DES (Data Encryption Standard) Implementasyonu
#
# UYARI: DES, 56-bit anahtar boyutu nedeniyle GÜVENSİZDİR.
#
# =============================================================================

def pad_key_to_8_bytes(key: bytes) -> bytes:
    """DES için anahtarı 8 byte'a ayarlar (kırpar veya doldurur)."""
    if len(key) > 8:
        return key[:8]
    elif len(key) < 8:
        return key.ljust(8, b'\0') # 8 byte'a 0 ile doldur
    return key

def encrypt_des(data: bytes, key: bytes) -> bytes:
    """
    Verilen datayı DES (CBC modu) ile şifreler.
    Çıktı olarak [iv (8 byte)] + [ciphertext] döndürür.
    """
    backend = default_backend()
    
    # Anahtarın tam olarak 8 byte olmasını sağla
    processed_key = pad_key_to_8_bytes(key)
    
    # 8 byte (64-bit) IV (Initialization Vector) oluştur
    iv = os.urandom(8)
    
    # DES şifresini CBC moduyla kur
    cipher = Cipher(algorithms.DES(processed_key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    
    # PKCS7 standardına göre padding ekle (DES blok boyutu 64 bit / 8 byte)
    padder = padding.PKCS7(algorithms.DES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    # Veriyi şifrele
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # IV'yi şifreli metnin başına ekle, böylece decrypt ederken kullanabiliriz
    return iv + ciphertext

def decrypt_des(token: bytes, key: bytes) -> bytes:
    """
    DES (CBC modu) ile şifrelenmiş token'ı çözer.
    Token'ın [iv (8 byte)] + [ciphertext] formatında olmasını bekler.
    """
    backend = default_backend()
    
    # Anahtarın tam olarak 8 byte olmasını sağla
    processed_key = pad_key_to_8_bytes(key)
    
    # IV ve şifreli metni ayır
    if len(token) < 8:
        raise ValueError("Bozuk veri: IV için yeterli uzunluk yok.")
        
    iv = token[:8]
    ciphertext = token[8:]
    
    # DES şifresini CBC moduyla kur
    cipher = Cipher(algorithms.DES(processed_key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    
    # Veriyi deşifrele
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # PKCS7 padding'ini kaldır
    unpadder = padding.PKCS7(algorithms.DES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    return data

# =============================================================================
#
# PLAYFAIR Cipher Implementasyonu
#
# UYARI: PLAYFAIR, klasik bir şifredir ve GÜVENSİZDİR.
#
# =============================================================================

def generate_playfair_matrix(key: str) -> list[list[str]]:
    """Playfair 5x5 matrisini oluşturur."""
    
    # Anahtarı hazırla: büyük harf, J'leri I yap, boşlukları kaldır
    key = key.upper().replace("J", "I").replace(" ", "")
    
    matrix_chars = []
    seen = set()
    
    # Önce anahtardaki harfleri ekle (sadece alfabetik)
    for char in key:
        if char not in seen and 'A' <= char <= 'Z':
            matrix_chars.append(char)
            seen.add(char)
            
    # Kalan alfabe harflerini ekle (J hariç)
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    for char in alphabet:
        if char not in seen:
            matrix_chars.append(char)
            
    # Listeyi 5x5 matrise dönüştür
    matrix = []
    for i in range(0, 25, 5):
        matrix.append(matrix_chars[i:i+5])
        
    return matrix

def find_position(matrix: list[list[str]], char: str) -> tuple[int, int]:
    """Matriste bir harfin (satır, sütun) konumunu bulur."""
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == char:
                return r, c
    # Bu durum normalde preprocess_text sayesinde yaşanmamalı
    return 0, 0 

def preprocess_text(text: str) -> str:
    """Playfair şifrelemesi için metni hazırlar."""
    # Sadece harfleri al, J'leri I yap, büyük harf yap
    text = re.sub(r'[^A-Z]', '', text.upper().replace("J", "I"))
    
    prepared_text = ""
    i = 0
    while i < len(text):
        a = text[i]
        
        # Son harf mi?
        if i == len(text) - 1:
            prepared_text += a + "X" # Tek kalan harfi X ile tamamla
            break
            
        b = text[i+1]
        
        # Harfler aynı mı?
        if a == b:
            prepared_text += a + "X" # Araya X ekle
            i += 1 # Sadece bir harf ilerle
        else:
            prepared_text += a + b
            i += 2 # İki harf ilerle
            
    # Metnin uzunluğu tek ise (aslında çift olmalı ama garantiye alalım)
    if len(prepared_text) % 2 != 0:
        prepared_text += "X"
        
    return prepared_text

def playfair_transform(text: str, key: str, mode: str = 'encrypt') -> str:
    """Playfair şifreleme veya deşifreleme yapar."""
    
    matrix = generate_playfair_matrix(key)
    
    # Şifreleme için metni hazırla
    if mode == 'encrypt':
        processed_text = preprocess_text(text)
    else:
        # Deşifreleme için metnin zaten hazır (çift harfli) olduğunu varsay
        processed_text = text.upper().replace("J", "I").replace(" ", "")
        if len(processed_text) % 2 != 0:
             raise ValueError("Şifreli metin çift sayıda harf içermelidir.")

    output_text = ""
    
    # Deşifre için kaydırma yönünü tersine çevir
    shift = 1 if mode == 'encrypt' else -1
    
    for i in range(0, len(processed_text), 2):
        char1 = processed_text[i]
        char2 = processed_text[i+1]
        
        r1, c1 = find_position(matrix, char1)
        r2, c2 = find_position(matrix, char1) # <-- Burası char1 olmalı, düzeltiyorum
        
        # Düzeltme:
        r2, c2 = find_position(matrix, char2)
        
        if r1 == r2: # Aynı satır
            output_text += matrix[r1][(c1 + shift) % 5]
            output_text += matrix[r2][(c2 + shift) % 5]
        elif c1 == c2: # Aynı sütun
            output_text += matrix[(r1 + shift) % 5][c1]
            output_text += matrix[(r2 + shift) % 5][c2]
        else: # Dikdörtgen
            output_text += matrix[r1][c2]
            output_text += matrix[r2][c1]
            
    return output_text

def encrypt_playfair(plaintext: str, key: str) -> str:
    """Playfair ile metni şifreler."""
    return playfair_transform(plaintext, key, mode='encrypt')

def decrypt_playfair(ciphertext: str, key: str) -> str:
    """Playfair ile şifrelenmiş metni çözer."""
    return playfair_transform(ciphertext, key, mode='decrypt')