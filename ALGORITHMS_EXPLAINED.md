# ŞİFRELEME ALGORİTMALARI - ÇALIŞMA MANTIĞI

## 🔐 SİMETRİK ŞİFRELEME ALGORİTMALARI

### 1. AES-256-GCM (Advanced Encryption Standard - Galois/Counter Mode)

**Temel Mantık:**
- **Block Cipher:** Veriyi 128-bit (16 byte) bloklara böler
- **Counter Mode:** Her blok için artan bir sayaç kullanır
- **Galois Mode:** Hem şifreler hem de authentication tag üretir

**Şifreleme Nasıl Çalışır?**
1. Anahtar (256-bit) ve IV (96-bit) alınır
2. Her blok için: `Counter + IV` ile keystream üretilir
3. `Ciphertext = Plaintext ⊕ Keystream` (XOR işlemi)
4. Galois field matematiği ile authentication tag hesaplanır
5. Ciphertext + Tag birlikte saklanır

**Deşifreleme:**
- Aynı keystream üretilir (aynı key + IV)
- `Plaintext = Ciphertext ⊕ Keystream`
- Authentication tag doğrulanır (veri değiştirilmiş mi?)

**Güvenlik:** Tag doğrulaması sayesinde hem şifreleme hem bütünlük koruması var.

---

### 2. AES-128-GCM

**Fark:** Anahtar 128-bit (16 byte), diğer her şey AES-256-GCM ile aynı.

**Neden Daha Küçük Anahtar?**
- Daha hızlı
- Hala çok güvenli (2^128 deneme gerekir)
- AES-256 daha fazla güvenlik marjı sağlar

---

### 3. ChaCha20-Poly1305

**Temel Mantık:**
- **Stream Cipher:** Blok değil, sürekli akış şifreler
- **ChaCha20:** Şifreleme kısmı
- **Poly1305:** Authentication kısmı

**Şifreleme Nasıl Çalışır?**
1. Anahtar (256-bit) ve Nonce (96-bit) alınır
2. ChaCha20 bir "pseudorandom stream" üretir
3. `Ciphertext = Plaintext ⊕ Stream`
4. Poly1305 ile authentication tag hesaplanır (MAC)

**Deşifreleme:**
- Aynı stream üretilir
- `Plaintext = Ciphertext ⊕ Stream`
- Poly1305 tag doğrulanır

**Avantaj:** AES donanım desteği olmayan cihazlarda daha hızlı (mobil, IoT).

---

### 4. AES-256-CBC (Cipher Block Chaining)

**Temel Mantık:**
- **Block Cipher:** Veriyi 128-bit bloklara böler
- **Chaining (Zincirleme):** Her blok bir öncekine bağlı

**Şifreleme Nasıl Çalışır?**
1. Veri PKCS7 padding ile blok boyutunun katı yapılır
2. İlk blok: `Ciphertext₁ = AES(Plaintext₁ ⊕ IV)`
3. Sonraki bloklar: `Ciphertext₂ = AES(Plaintext₂ ⊕ Ciphertext₁)`
4. Zincirleme devam eder

**Deşifreleme:**
1. `Plaintext₁ = AES_Decrypt(Ciphertext₁) ⊕ IV`
2. `Plaintext₂ = AES_Decrypt(Ciphertext₂) ⊕ Ciphertext₁`
3. PKCS7 padding kaldırılır

**Önemli:** CBC kendisi authentication sağlamaz, HMAC ile birlikte kullanılır.

---

### 5. DES (Data Encryption Standard) ⚠️

**Temel Mantık:**
- **Feistel Network:** Veriyi iki yarıya böl, değiştir, karıştır
- **16 Round:** 16 kez tekrarla

**Şifreleme Nasıl Çalışır?**
1. 64-bit veriyi sol (L) ve sağ (R) olmak üzere ikiye böl
2. Her round: `L₁ = R₀` ve `R₁ = L₀ ⊕ F(R₀, K₁)`
3. F fonksiyonu: Substitution (S-boxes) ve Permutation
4. 16 round sonra birleştir

**Neden Güvensiz?**
- 56-bit anahtar çok küçük
- Modern bilgisayarlar brute-force ile kırabilir
- 1998'de 56 saatte kırıldı, bugün dakikalar sürer

---

## 🔑 ASİMETRİK ŞİFRELEME

### 6. RSA-OAEP-4096

**Temel Mantık:**
- **İki Anahtar:** Public key (şifreler), Private key (deşifreler)
- **Büyük Sayı Matematiği:** Asal çarpanlarına ayırma zor

**Nasıl Çalışır?**

**Anahtar Üretimi:**
1. İki büyük asal sayı seç: p, q
2. `n = p × q` (4096-bit)
3. `φ(n) = (p-1)(q-1)`
4. Public key: (n, e=65537)
5. Private key: (n, d) where `d × e ≡ 1 (mod φ(n))`

**Şifreleme:**
1. OAEP padding ekle (randomness + hash)
2. `Ciphertext = Message^e mod n`

**Deşifreleme:**
1. `Message = Ciphertext^d mod n`
2. OAEP padding kaldır

**Güvenlik:**
- n'yi p ve q'ya ayırmak zor (factorization problem)
- 4096-bit yeterince büyük
- Sadece küçük veri şifreleyebilir (max ~500 byte)

**Neden Hybrid Encryption?**
- RSA yavaş, büyük veri için uygun değil
- Symmetric key'i RSA ile şifrele
- Veriyi symmetric ile şifrele
- En iyi ikisini al!

---

## ✅ BÜTÜNLÜK DOĞRULAMA

### 7. HMAC-SHA256

**Temel Mantık:**
- **Hash:** Veriyi sabit boyutlu özete çevir
- **MAC:** Anahtar ile hash'le (sadece anahtar sahibi doğru hash üretebilir)

**Nasıl Çalışır?**

**HMAC Formülü:**
```
HMAC(K, M) = H((K ⊕ opad) || H((K ⊕ ipad) || M))
```

**Adım Adım:**
1. Anahtar (K) ve mesaj (M) al
2. İç hash: `H(K ⊕ ipad || M)` hesapla
3. Dış hash: `H(K ⊕ opad || inner_hash)` hesapla
4. Sonuç: 256-bit tag

**Doğrulama:**
1. Aynı işlemi tekrarla
2. Tag'leri karşılaştır (constant-time)
3. Eşleşiyorsa → veri değişmemiş
4. Eşleşmiyorsa → veri değiştirilmiş veya yanlış anahtar

**Neden İki Hash?**
- Length extension attack'e karşı koruma
- Daha güvenli yapı

---

## 📜 KLASİK ŞİFRELER

### 8. Playfair Cipher

**Temel Mantık:**
- 5×5 matrix üzerinde harf çiftlerini şifrele
- Polygraphic substitution (birden fazla harf birlikte)

**Nasıl Çalışır?**

**Matrix Oluşturma:**
1. Anahtar kelimeyi matrise yerleştir (tekrarsız)
2. Kalan harfleri ekle (J=I)

**Şifreleme Kuralları:**
1. **Aynı satır:** Sağa kaydır
2. **Aynı sütun:** Aşağı kaydır
3. **Dikdörtgen:** Köşegenleri değiştir

**Örnek:**
```
Matrix:      H E L O A
             B C D F G
             I K M N P
             Q R S T U
             V W X Y Z

"HE" → "EL" (aynı satır, sağa kaydır)
"LL" → "LX" (aynı harfler, X ekle sonra şifrele)
"HI" → "IH" (dikdörtgen, köşegen değiş)
```

**Neden Güvensiz?**
- Frekans analizi ile kırılır
- Sadece 25! ≈ 10^25 olası matrix (brute-force edilebilir)
- Digraph frekansları belirgin

---

## 🔄 SİSTEMDE KULLANIM

### Multi-Layer Encryption (Katmanlı Şifreleme)

**Şifreleme Akışı:**
```
PDF → [Layer1: AES-256-GCM] → Ciphertext1
      → [Layer2: ChaCha20] → Ciphertext2
      → [HMAC-SHA256] → Tag
      → Encrypted File

Symmetric Keys → [RSA-4096] → Encrypted Keys → Key File
```

**Deşifreleme Akışı:**
```
Key File → [RSA-4096] → Symmetric Keys

Encrypted File → [HMAC Check] → Valid?
               → [ChaCha20] → Plaintext1
               → [AES-256-GCM] → PDF
```

**Neden İki Katman?**
1. **Defense in Depth:** Biri kırılsa diğeri korur
2. **Algorithm Agility:** Farklı algoritmaların güçlü yönlerini kullan
3. **Future-Proof:** Yeni saldırılara karşı daha dayanıklı

---

## 🛡️ GÜVENLİK PRENSİPLERİ

### 1. Kerckhoffs Prensibi
**"Güvenlik anahtarda, algoritmada değil"**
- Hangi algoritma kullanıldığı açık
- Sadece anahtar gizli
- Algorithm secrecy ≠ security

### 2. Perfect Forward Secrecy
**Her dosya için yeni anahtarlar**
- Bir anahtar ele geçirilse diğer dosyalar güvende
- Session isolation

### 3. Authenticated Encryption
**Şifreleme + Bütünlük birlikte**
- Encrypt-then-MAC yaklaşımı
- Tamper detection
- CCA (Chosen Ciphertext Attack) koruması

### 4. Defense in Depth
**Çoklu güvenlik katmanları**
- 2 farklı symmetric algorithm
- RSA key encapsulation
- HMAC integrity check
- 3 seviye koruma

---

## 📊 KARŞILAŞTIRMA

| Algoritma | Güvenlik | Hız | Kullanım |
|-----------|----------|-----|----------|
| **AES-256-GCM** | ⭐⭐⭐⭐⭐ | ⚡⚡⚡ | Veri şifreleme |
| **ChaCha20** | ⭐⭐⭐⭐⭐ | ⚡⚡ | Mobil cihazlar |
| **AES-CBC** | ⭐⭐⭐⭐ | ⚡⚡⚡ | Legacy sistemler |
| **DES** | ⚠️ Kırık | ⚡ | Sadece akademik |
| **RSA-4096** | ⭐⭐⭐⭐⭐ | 🐌 | Anahtar değişimi |
| **HMAC-SHA256** | ⭐⭐⭐⭐⭐ | ⚡⚡⚡ | Bütünlük kontrolü |
| **Playfair** | ⚠️ Kırık | 👤 | Tarihi gösterim |

---

## 🎯 ÖZET

**Simetrik Algoritmalar:**
- Aynı anahtar şifreler ve deşifreler
- Hızlı, büyük veri için ideal
- AES = Block cipher, ChaCha20 = Stream cipher

**Asimetrik Algoritmalar:**
- Public key şifreler, private key deşifreler
- Yavaş, sadece küçük veri (anahtarlar) için
- RSA = Büyük sayı matematiği

**Authentication:**
- HMAC = Veri değişmemiş mi kontrol et
- GCM/Poly1305 = Built-in authentication
- Encrypt-then-MAC = En güvenli yaklaşım

**Sistem Mimarisi:**
- Hybrid encryption (RSA + Symmetric)
- Multi-layer defense
- Kerckhoffs prensibi
- Perfect forward secrecy
