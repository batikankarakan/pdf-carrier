# PDF CARRIER SİSTEMİNDE KULLANILAN ŞİFRELEME ALGORİTMALARI

## 📚 İÇİNDEKİLER
1. **Simetrik Şifreleme Algoritmaları**
   - AES-256-GCM
   - AES-128-GCM
   - ChaCha20-Poly1305
   - AES-256-CBC
   - DES (Güvensiz - Akademik Amaçlı)

2. **Asimetrik Şifreleme**
   - RSA-OAEP-4096

3. **Bütünlük Doğrulama**
   - HMAC-SHA256

4. **Klasik Şifreler** (Akademik)
   - Playfair

5. **Genel Akış**

---

## 1️⃣ AES-256-GCM (Advanced Encryption Standard - Galois/Counter Mode)

### 📖 Genel Açıklama
- **Tip:** Simetrik, Blok Şifreleme (Authenticated Encryption)
- **Anahtar Boyutu:** 256 bit (32 byte)
- **Blok Boyutu:** 128 bit (16 byte)
- **IV Boyutu:** 96 bit (12 byte)
- **Güvenlik:** Çok Yüksek (NIST onaylı)

### 🔐 ŞİFRELEME AŞAMASI (Encryption)

**Adım 1: Anahtar Üretimi**
```python
def generate_key() -> bytes:
    return secrets.token_bytes(32)  # 256 bit rastgele anahtar
```
- Kriptografik olarak güvenli rastgele sayı üreteci kullanılır
- 32 byte = 256 bit güçlü anahtar

**Adım 2: IV (Initialization Vector) Üretimi**
```python
iv = os.urandom(12)  # 96 bit
```
- Her şifreleme için UNIQUE (benzersiz) bir IV oluşturulur
- IV'nin tekrar kullanılması GÜVENLİK AÇIĞI oluşturur
- 12 byte (96 bit) GCM modu için optimal boyuttur

**Adım 3: AESGCM Cipher Nesnesi Oluşturma**
```python
aesgcm = AESGCM(key)
```
- Cryptography kütüphanesi AESGCM sınıfı kullanılır
- Anahtar cipher nesnesine yüklenir

**Adım 4: Şifreleme İşlemi**
```python
ciphertext = aesgcm.encrypt(iv, plaintext, None)
```
- `plaintext`: Şifrelenecek veri (PDF bytes)
- `iv`: Initialization Vector
- `None`: Associated Data (isteğe bağlı, kullanmıyoruz)
- **Çıktı:** Şifreli metin + Authentication Tag (16 byte)

**Ne Oluyor?**
1. AES blok şifreleme algoritması Counter Mode'da çalışır
2. Galois mode ile authentication tag üretilir
3. Veri hem şifrelenir hem de bütünlük koruması eklenir

### 🔓 DEŞİFRELEME AŞAMASI (Decryption)

**Adım 1: AESGCM Cipher Nesnesi Oluşturma**
```python
aesgcm = AESGCM(key)
```
- Aynı anahtar kullanılır

**Adım 2: Deşifreleme İşlemi**
```python
plaintext = aesgcm.decrypt(iv, ciphertext, None)
```
- `iv`: Şifreleme sırasında kullanılan IV
- `ciphertext`: Şifreli veri + authentication tag
- **Otomatik:** Authentication tag doğrulanır
- Eğer veri değiştirilmişse `InvalidTag` exception fırlatılır

**Ne Oluyor?**
1. Authentication tag doğrulanır (tamper detection)
2. AES Counter Mode ile veri deşifrelenir
3. Orijinal plaintext elde edilir

**Dosya Konumu:** [backend/crypto/algorithms.py:26-80](backend/crypto/algorithms.py#L26-L80)

---

## 2️⃣ AES-128-GCM

### 📖 Genel Açıklama
- AES-256-GCM ile aynı mantık
- **Tek Fark:** Anahtar boyutu 128 bit (16 byte)
- Daha hızlı ama AES-256'dan daha az güvenlik marjı

### 🔐 ŞİFRELEME
```python
key = secrets.token_bytes(16)  # 128 bit
iv = os.urandom(12)
aesgcm = AESGCM(key)
ciphertext = aesgcm.encrypt(iv, plaintext, None)
```

### 🔓 DEŞİFRELEME
```python
aesgcm = AESGCM(key)
plaintext = aesgcm.decrypt(iv, ciphertext, None)
```

**Dosya Konumu:** [backend/crypto/algorithms.py:328-373](backend/crypto/algorithms.py#L328-L373)

---

## 3️⃣ ChaCha20-Poly1305

### 📖 Genel Açıklama
- **Tip:** Stream Cipher + MAC (Authenticated Encryption)
- **Anahtar Boyutu:** 256 bit (32 byte)
- **Nonce Boyutu:** 96 bit (12 byte)
- **Avantaj:** AES donanım desteği olmayan sistemlerde daha hızlı
- **Güvenlik:** AES-256-GCM ile eşdeğer

### 🔐 ŞİFRELEME AŞAMASI

**Adım 1: Anahtar Üretimi**
```python
key = secrets.token_bytes(32)  # 256 bit
```

**Adım 2: Nonce Üretimi**
```python
nonce = os.urandom(12)  # 96 bit
```
- Nonce = "Number used once"
- Her şifreleme için benzersiz olmalı

**Adım 3: ChaCha20Poly1305 Cipher**
```python
chacha = ChaCha20Poly1305(key)
ciphertext = chacha.encrypt(nonce, plaintext, None)
```

**Ne Oluyor?**
1. ChaCha20 stream cipher ile veri şifrelenir
2. Poly1305 MAC ile authentication tag üretilir
3. Çıktı: Ciphertext + 16 byte Poly1305 tag

### 🔓 DEŞİFRELEME AŞAMASI

```python
chacha = ChaCha20Poly1305(key)
plaintext = chacha.decrypt(nonce, ciphertext, None)
```
- Poly1305 tag otomatik doğrulanır
- Tamper edilmişse `InvalidTag` hatası

**Dosya Konumu:** [backend/crypto/algorithms.py:83-136](backend/crypto/algorithms.py#L83-L136)

---

## 4️⃣ AES-256-CBC (Cipher Block Chaining)

### 📖 Genel Açıklama
- **Tip:** Blok Şifreleme Modu (Geleneksel)
- **Anahtar Boyutu:** 256 bit (32 byte)
- **IV Boyutu:** 128 bit (16 byte)
- **Padding:** PKCS7
- **Not:** Authentication GCM gibi built-in değil, dış HMAC kullanıyoruz

### 🔐 ŞİFRELEME AŞAMASI

**Adım 1: Anahtar Üretimi**
```python
key = secrets.token_bytes(32)  # 256 bit
```

**Adım 2: PKCS7 Padding Ekleme**
```python
padder = sym_padding.PKCS7(128).padder()
padded_data = padder.update(plaintext) + padder.finalize()
```
**Neden Padding?**
- AES blok boyutu 128 bit (16 byte)
- Veri bu boyutun katı olmalı
- PKCS7: Eksik byte sayısı kadar byte ekler
- Örnek: 5 byte eksikse, her biri `0x05` olan 5 byte ekler

**Adım 3: IV Üretimi**
```python
iv = os.urandom(16)  # 128 bit
```

**Adım 4: AES-CBC Cipher Oluşturma**
```python
cipher = Cipher(
    algorithms.AES(key),
    modes.CBC(iv),
    backend=default_backend()
)
encryptor = cipher.encryptor()
```

**Adım 5: Şifreleme**
```python
ciphertext = encryptor.update(padded_data) + encryptor.finalize()
```

**CBC Nasıl Çalışır?**
1. İlk blok IV ile XOR'lanır ve şifrelenir
2. İkinci blok, birinci blokun ciphertext'i ile XOR'lanır
3. Bu zincirleme devam eder
4. Bir bloktaki değişiklik sonraki tüm blokları etkiler

### 🔓 DEŞİFRELEME AŞAMASI

**Adım 1: Cipher Oluşturma**
```python
cipher = Cipher(
    algorithms.AES(key),
    modes.CBC(iv),
    backend=default_backend()
)
decryptor = cipher.decryptor()
```

**Adım 2: Deşifreleme**
```python
padded_data = decryptor.update(ciphertext) + decryptor.finalize()
```

**Adım 3: Padding Kaldırma**
```python
unpadder = sym_padding.PKCS7(128).unpadder()
plaintext = unpadder.update(padded_data) + unpadder.finalize()
```

**Dosya Konumu:** [backend/crypto/algorithms.py:376-450](backend/crypto/algorithms.py#L376-L450)

---

## 5️⃣ DES (Data Encryption Standard) ⚠️ GÜVENSİZ

### 📖 Genel Açıklama
- **Anahtar Boyutu:** 56 bit (8 byte efektif)
- **Blok Boyutu:** 64 bit (8 byte)
- **Durum:** KRİPTOGRAFİK OLARAK KIRILMIŞ
- **Kullanım:** Sadece akademik ve tarihsel gösterim

### 🔐 ŞİFRELEME AŞAMASI

**Adım 1: Anahtar Hazırlama**
```python
def pad_key_to_8_bytes(key: bytes) -> bytes:
    if len(key) > 8:
        return key[:8]  # Fazlasını kes
    elif len(key) < 8:
        return key.ljust(8, b'\0')  # 8 byte'a tamamla
    return key
```

**Adım 2: IV Üretimi**
```python
iv = os.urandom(8)  # 64 bit
```

**Adım 3: PKCS7 Padding (64-bit bloklar için)**
```python
padder = padding.PKCS7(64).padder()
padded_data = padder.update(data) + padder.finalize()
```

**Adım 4: TripleDES ile Emülasyon**
```python
triple_key = key + key + key  # 8+8+8=24 bytes
cipher = Cipher(
    TripleDES(triple_key),
    modes.CBC(iv),
    backend=default_backend()
)
encryptor = cipher.encryptor()
ciphertext = encryptor.update(padded_data) + encryptor.finalize()
```
**Not:** Modern cryptography kütüphaneleri pure DES desteğini kaldırdı, TripleDES ile emüle ediyoruz

**Adım 5: IV + Ciphertext Birleştirme**
```python
return iv + ciphertext
```

### 🔓 DEŞİFRELEME AŞAMASI

**Adım 1: IV ve Ciphertext Ayırma**
```python
iv = token[:8]
ciphertext = token[8:]
```

**Adım 2: Deşifreleme**
```python
triple_key = key + key + key
cipher = Cipher(TripleDES(triple_key), modes.CBC(iv))
decryptor = cipher.decryptor()
padded_data = decryptor.update(ciphertext) + decryptor.finalize()
```

**Adım 3: Padding Kaldırma**
```python
unpadder = padding.PKCS7(64).unpadder()
data = unpadder.update(padded_data) + unpadder.finalize()
```

**Dosya Konumu:** [backend/crypto/algorithms.py:453-548](backend/crypto/algorithms.py#L453-L548)

**DES API Kullanımı:** [backend/crypto/classic_ciphers.py:35-90](backend/crypto/classic_ciphers.py#L35-L90)

---

## 6️⃣ RSA-OAEP-4096 (Asymmetric Key Encapsulation)

### 📖 Genel Açıklama
- **Tip:** Asimetrik Şifreleme
- **Anahtar Boyutu:** 4096 bit
- **Padding:** OAEP (Optimal Asymmetric Encryption Padding)
- **Hash:** SHA-256
- **Kullanım:** Simetrik anahtarları şifrelemek (Key Encapsulation)

### 🔑 ANAHTAR ÇİFTİ ÜRETİMİ

```python
private_key = rsa.generate_private_key(
    public_exponent=65537,  # Standard e değeri
    key_size=4096           # 4096-bit güvenlik
)
public_key = private_key.public_key()
```

**Ne Oluyor?**
1. İki büyük asal sayı (p, q) üretilir
2. n = p × q hesaplanır (4096 bit)
3. φ(n) = (p-1)(q-1) hesaplanır
4. e = 65537 seçilir (public exponent)
5. d hesaplanır: d × e ≡ 1 (mod φ(n))

**Public Key:** (n, e)
**Private Key:** (n, d, p, q, ...)

### 🔐 ŞİFRELEME AŞAMASI

```python
ciphertext = public_key.encrypt(
    plaintext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
```

**OAEP Padding Aşamaları:**
1. **Hash:** plaintext SHA-256 ile hash'lenir
2. **MGF1:** Mask Generation Function ile mask üretilir
3. **XOR:** plaintext mask ile XOR'lanır
4. **RSA:** Padded message modular exponentiation ile şifrelenir

**Matematiksel:**
```
C = M^e mod n
```
- M: Padded plaintext
- e: Public exponent (65537)
- n: Modulus (4096-bit)

### 🔓 DEŞİFRELEME AŞAMASI

```python
plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
```

**Matematiksel:**
```
M = C^d mod n
```
- C: Ciphertext
- d: Private exponent (secret!)
- n: Modulus

**OAEP Unpadding:**
1. RSA deşifreleme
2. MGF1 ile mask çıkarılır
3. Hash doğrulanır
4. Orijinal plaintext elde edilir

**Dosya Konumu:** [backend/crypto/algorithms.py:139-271](backend/crypto/algorithms.py#L139-L271)

---

## 7️⃣ HMAC-SHA256 (Message Authentication Code)

### 📖 Genel Açıklama
- **Tip:** Hash-based Message Authentication
- **Anahtar Boyutu:** 256 bit (32 byte)
- **Çıktı Boyutu:** 256 bit (32 byte)
- **Amaç:** Veri bütünlüğü doğrulama

### 🔐 HMAC HESAPLAMA

**Adım 1: Anahtar Üretimi**
```python
key = secrets.token_bytes(32)  # 256 bit
```

**Adım 2: HMAC Hesaplama**
```python
h = hmac.HMAC(key, hashes.SHA256())
h.update(data)
tag = h.finalize()  # 32-byte HMAC tag
```

**HMAC Formülü:**
```
HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))
```
- K: Secret key
- m: Message
- H: SHA-256 hash function
- opad: Outer padding (0x5c tekrarı)
- ipad: Inner padding (0x36 tekrarı)
- ||: Concatenation (birleştirme)
- ⊕: XOR

### ✅ HMAC DOĞRULAMA

```python
h = hmac.HMAC(key, hashes.SHA256())
h.update(data)
try:
    h.verify(expected_hmac)
    return True  # HMAC geçerli
except Exception:
    return False  # Veri değiştirilmiş
```

**Constant-Time Comparison:**
- Timing attack'lara karşı koruma
- Byte-by-byte karşılaştırma aynı sürer

**Dosya Konumu:** [backend/crypto/algorithms.py:273-325](backend/crypto/algorithms.py#L273-L325)

---

## 8️⃣ PLAYFAIR ŞİFRESİ (Klasik - Güvensiz)

### 📖 Genel Açıklama
- **Tip:** Manuel, 5×5 matrix tabanlı
- **Tarih:** 1854
- **Durum:** Frekans analiziyle kolayca kırılır
- **Kullanım:** Sadece tarihsel gösterim

### 🔐 ŞİFRELEME AŞAMASI

**Adım 1: 5×5 Matrix Oluşturma**
```python
def generate_playfair_matrix(key: str) -> list[list[str]]:
    key = key.upper().replace("J", "I")  # J = I
    matrix_chars = []
    seen = set()

    # Önce key'deki harfler
    for char in key:
        if char not in seen and 'A' <= char <= 'Z':
            matrix_chars.append(char)
            seen.add(char)

    # Kalan alfabe (J hariç)
    for char in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if char not in seen:
            matrix_chars.append(char)

    # 5×5 matris
    return [matrix_chars[i:i+5] for i in range(0, 25, 5)]
```

**Örnek Matrix (key="HELLO"):**
```
H E L O A
B C D F G
I K M N P
Q R S T U
V W X Y Z
```

**Adım 2: Text Preprocessing**
```python
def preprocess_text(text: str) -> str:
    text = text.upper().replace("J", "I")
    text = re.sub(r'[^A-Z]', '', text)  # Sadece harfler

    prepared = ""
    i = 0
    while i < len(text):
        a = text[i]
        if i == len(text) - 1:
            prepared += a + "X"  # Tek kalan harf
            break
        b = text[i+1]
        if a == b:
            prepared += a + "X"  # Aynı harfler
            i += 1
        else:
            prepared += a + b
            i += 2

    return prepared
```

**Örnek:** "HELLO" → "HEL**X**LO" (LL ayrıldı)

**Adım 3: Çift Harfleri Şifreleme**
3 kural var:

**Kural 1: Aynı satırdaysalar**
- Her harfi 1 sağa kaydır (wrap around)
```
HE → EL
```

**Kural 2: Aynı sütundaysalar**
- Her harfi 1 aşağı kaydır (wrap around)

**Kural 3: Dikdörtgen oluşturuyorlarsa**
- Her harf, diğerinin sütunundaki harfle değişir
```
H(0,0) E(0,1) → E(0,1) H(0,0)  (satırları aynı tut, sütunları değiştir)
```

### 🔓 DEŞİFRELEME AŞAMASI

Aynı kurallar, ters yönde:
- Aynı satır → 1 sola kaydır
- Aynı sütun → 1 yukarı kaydır
- Dikdörtgen → Aynı (simetrik)

**Dosya Konumu:** [backend/crypto/classic_ciphers.py:100-215](backend/crypto/classic_ciphers.py#L100-L215)

---

## 🔄 SİSTEMİN GENEL AKIŞI

### ŞİFRELEME AKIŞI

```
1. PDF Dosyası Yüklenir
   ↓
2. RSA Anahtar Çifti Üretilir (4096-bit)
   ↓
3. İki Algoritma Seçilir (Rastgele veya manuel)
   Örnek: [AES-256-GCM, ChaCha20-Poly1305]
   ↓
4. Layer 1 Şifreleme (AES-256-GCM)
   - AES key üretilir (32 byte)
   - IV üretilir (12 byte)
   - PDF şifrelenir → Ciphertext1
   ↓
5. Layer 2 Şifreleme (ChaCha20-Poly1305)
   - ChaCha key üretilir (32 byte)
   - Nonce üretilir (12 byte)
   - Ciphertext1 şifrelenir → Ciphertext2
   ↓
6. Symmetric Keys Blob Oluşturma
   keys_blob = AES_key + ChaCha_key (64 bytes)
   ↓
7. RSA ile Keys Blob Şifreleme
   encrypted_keys = RSA_encrypt(keys_blob, public_key)
   ↓
8. HMAC Hesaplama
   hmac_key üretilir (32 byte)
   hmac_tag = HMAC-SHA256(Ciphertext2, hmac_key)
   ↓
9. JSON Dosya Oluşturma
   {
     "header": {
       "algorithms": ["AES-256-GCM", "ChaCha20-Poly1305"],
       "layer1_iv": "...",
       "layer2_nonce": "...",
       "encrypted_symmetric_keys": "...",
       "hmac_key": "..."
     },
     "ciphertext": "base64(Ciphertext2)",
     "hmac": "base64(hmac_tag)"
   }
   ↓
10. Key File Oluşturma
    {
      "private_key_pem": "...",
      "public_key_pem": "...",
      "algorithm_pool": ["AES-256-GCM", "ChaCha20-Poly1305"]
    }
```

**Kod Referansı:** [backend/crypto/encryption.py:53-195](backend/crypto/encryption.py#L53-L195)

### DEŞİFRELEME AKIŞI

```
1. Encrypted File + Key File Yüklenir
   ↓
2. Key File Parse Edilir
   - RSA private key yüklenir
   ↓
3. Encrypted File Parse Edilir
   - Header, ciphertext, hmac ayrıştırılır
   ↓
4. HMAC Doğrulama
   computed_hmac = HMAC-SHA256(ciphertext, hmac_key)
   if computed_hmac != expected_hmac:
       raise "File tampered!"
   ↓
5. RSA ile Symmetric Keys Deşifreleme
   keys_blob = RSA_decrypt(encrypted_keys, private_key)
   ↓
6. Keys Blob'u Ayırma
   - Layer1_key = keys_blob[0:32]   (AES key)
   - Layer2_key = keys_blob[32:64]  (ChaCha key)
   ↓
7. REVERSE ORDER Deşifreleme
   Layer 2 First (ChaCha20-Poly1305):
     - nonce = header["layer2_nonce"]
     - plaintext1 = ChaCha_decrypt(ciphertext, layer2_key, nonce)
   ↓
8. Layer 1 Deşifreleme (AES-256-GCM):
     - iv = header["layer1_iv"]
     - pdf_bytes = AES_decrypt(plaintext1, layer1_key, iv)
   ↓
9. Orijinal PDF Elde Edilir
```

**Kod Referansı:** [backend/crypto/decryption.py:20-179](backend/crypto/decryption.py#L20-L179)

---

## 🔒 GÜVENLİK PRENSİPLERİ

### 1. **Kerckhoffs Prensibi**
- Algoritma açık (public), anahtar gizli
- Hangi algoritmanın kullanıldığı metadata'da yazıyor
- Güvenlik sadece anahtar gizliliğine dayanır

### 2. **Defense in Depth (Katmanlı Savunma)**
- İki farklı algoritma kullanılır
- Biri kırılsa bile diğeri korur

### 3. **Perfect Forward Secrecy**
- Her dosya için yeni anahtarlar üretilir
- Bir dosyanın anahtarı ele geçirilse diğerleri güvende

### 4. **Authenticated Encryption**
- GCM ve ChaCha20-Poly1305 hem şifreler hem doğrular
- Tampering otomatik tespit edilir

### 5. **HMAC Integrity Check**
- Ek bir bütünlük katmanı
- Dosya değiştirilmiş mi kontrol eder

---

## 📊 ALGORİTMA KARŞILAŞTIRMA TABLOSU

| Algoritma | Tip | Anahtar Boyutu | Güvenlik | Hız | Donanım Desteği |
|-----------|-----|----------------|----------|-----|-----------------|
| AES-256-GCM | Simetrik | 256 bit | Çok Yüksek | Çok Hızlı | ✅ AES-NI |
| AES-128-GCM | Simetrik | 128 bit | Yüksek | Çok Hızlı | ✅ AES-NI |
| ChaCha20-Poly1305 | Simetrik | 256 bit | Çok Yüksek | Hızlı | ❌ Yazılımsal |
| AES-256-CBC | Simetrik | 256 bit | Yüksek | Hızlı | ✅ AES-NI |
| DES | Simetrik | 56 bit | ⚠️ Kırık | Orta | ❌ Legacy |
| RSA-4096 | Asimetrik | 4096 bit | Çok Yüksek | Yavaş | ❌ Yazılımsal |
| HMAC-SHA256 | MAC | 256 bit | Çok Yüksek | Hızlı | ✅ SHA-NI |
| Playfair | Klasik | Değişken | ⚠️ Kırık | Manuel | ❌ Elle |

---

## 🎓 HOCAYA SUNUM ÖNERİSİ

### Sunum Sırası:

1. **Giriş (5 dk)**
   - Projenin amacı
   - Kullanılan teknolojiler
   - Kerckhoffs Prensibi

2. **Simetrik Algoritmalar (15 dk)**
   - AES-256-GCM detaylı anlatım
   - Diğer simetrik algoritmaların karşılaştırması
   - IV/Nonce kullanımının önemi

3. **Asimetrik Şifreleme (10 dk)**
   - RSA-OAEP-4096
   - Key encapsulation mekanizması
   - Public/Private key mantığı

4. **Bütünlük Doğrulama (5 dk)**
   - HMAC-SHA256
   - Tamper detection

5. **Katmanlı Şifreleme (10 dk)**
   - Multi-layer encryption akışı
   - Şifreleme adımları (canlı demo)
   - Deşifreleme adımları (canlı demo)

6. **Güvenlik Prensipleri (5 dk)**
   - Defense in depth
   - Perfect forward secrecy
   - Authenticated encryption

7. **Akademik Algoritmalar (5 dk)**
   - DES tarihi ve güvenlik açıkları
   - Playfair şifresi

8. **Canlı Demo (10 dk)**
   - Bir PDF'i şifreleme
   - Metadata inceleme
   - Deşifreleme

### Demo Komutları:

```bash
# Backend başlat
cd backend
source venv/bin/activate  # veya Windows'ta: venv\Scripts\activate
python main.py

# Frontend başlat
cd frontend
npm run dev

# Tarayıcıda aç
open http://localhost:5173
```

---

## 📚 EK KAYNAKLAR

### Akademik Makaleler:
- NIST SP 800-38D: "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)"
- RFC 7539: "ChaCha20 and Poly1305 for IETF Protocols"
- RFC 8017: "PKCS #1: RSA Cryptography Specifications Version 2.2"

### Kütüphaneler:
- [Cryptography.io](https://cryptography.io/) - Python cryptography kütüphanesi
- [PyCA](https://github.com/pyca/cryptography) - GitHub repository

### Güvenlik Standartları:
- NIST (National Institute of Standards and Technology)
- FIPS 140-2 (Federal Information Processing Standards)

---

## 📞 İLETİŞİM

Proje Hakkında Sorular:
- GitHub: [pdf-carrier](https://github.com/yourusername/pdf-carrier)
- Email: your.email@example.com

---

**Son Güncelleme:** 2025-11-09
**Versiyon:** 2.0
**Yazar:** PDF Carrier Team
