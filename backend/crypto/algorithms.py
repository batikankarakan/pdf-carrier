"""
Cryptographic Algorithms Implementation

This module implements the core encryption algorithms:
- AES-256-GCM: Symmetric encryption with authentication
- AES-128-GCM: Symmetric encryption with authentication (128-bit)
- ChaCha20-Poly1305: Alternative symmetric encryption
- AES-256-CBC: Traditional block cipher mode with PKCS7 padding
- RSA-OAEP: Asymmetric key encapsulation
- HMAC-SHA256: Message authentication

All algorithms use industry-standard libraries and follow best practices.
"""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os
import secrets
from typing import Tuple, Dict

# Import our custom key generation algorithm
from .cryptography import CascadingEntropyMixer

# Global key generator instance
_key_generator = CascadingEntropyMixer(rounds=7, pool_size=64)


class AESGCMCipher:
    """AES-256-GCM encryption/decryption"""

    @staticmethod
    def generate_key() -> bytes:
        """
        Generate a 256-bit (32 bytes) AES key using Cascading Entropy Mixer

        Returns:
            bytes: 32-byte AES key
        """
        return _key_generator.generate_key(32)  # 256 bits

    @staticmethod
    def generate_iv() -> bytes:
        """
        Generate a 96-bit (12 bytes) IV using os.urandom for guaranteed uniqueness

        Returns:
            bytes: 12-byte IV
        """
        # Use os.urandom directly for IVs/nonces to guarantee uniqueness
        # IVs must NEVER repeat for the same key in GCM mode
        return os.urandom(12)

    @staticmethod
    def encrypt(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt plaintext using AES-256-GCM

        AES-GCM provides both confidentiality and authenticity.
        The authentication tag is automatically appended to the ciphertext.

        Args:
            plaintext: Data to encrypt
            key: 32-byte AES key

        Returns:
            Tuple of (ciphertext, iv)
        """
        aesgcm = AESGCM(key)
        iv = os.urandom(12)  # 96 bits - MUST be unique for each encryption
        ciphertext = aesgcm.encrypt(iv, plaintext, None)
        return ciphertext, iv

    @staticmethod
    def decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        """
        Decrypt ciphertext using AES-256-GCM

        Automatically verifies the authentication tag.
        Raises exception if tampered.

        Args:
            ciphertext: Encrypted data (includes auth tag)
            key: 32-byte AES key
            iv: 12-byte initialization vector

        Returns:
            bytes: Decrypted plaintext

        Raises:
            cryptography.exceptions.InvalidTag: If data has been tampered with
        """
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(iv, ciphertext, None)
        return plaintext


class ChaCha20Cipher:
    """ChaCha20-Poly1305 encryption/decryption"""

    @staticmethod
    def generate_key() -> bytes:
        """
        Generate a 256-bit (32 bytes) ChaCha20 key using Cascading Entropy Mixer

        Returns:
            bytes: 32-byte ChaCha20 key
        """
        return _key_generator.generate_key(32)

    @staticmethod
    def generate_nonce() -> bytes:
        """
        Generate a 96-bit (12 bytes) nonce using os.urandom for guaranteed uniqueness

        Returns:
            bytes: 12-byte nonce
        """
        # Use os.urandom directly for nonces to guarantee uniqueness
        # Nonces must NEVER repeat for the same key
        return os.urandom(12)

    @staticmethod
    def encrypt(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt plaintext using ChaCha20-Poly1305

        ChaCha20-Poly1305 provides authenticated encryption like AES-GCM,
        but is more efficient on systems without AES hardware acceleration.

        Args:
            plaintext: Data to encrypt
            key: 32-byte ChaCha20 key

        Returns:
            Tuple of (ciphertext, nonce)
        """
        chacha = ChaCha20Poly1305(key)
        nonce = os.urandom(12)  # 96 bits - MUST be unique
        ciphertext = chacha.encrypt(nonce, plaintext, None)
        return ciphertext, nonce

    @staticmethod
    def decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
        """
        Decrypt ciphertext using ChaCha20-Poly1305

        Automatically verifies the authentication tag.

        Args:
            ciphertext: Encrypted data (includes auth tag)
            key: 32-byte ChaCha20 key
            nonce: 12-byte nonce

        Returns:
            bytes: Decrypted plaintext

        Raises:
            cryptography.exceptions.InvalidTag: If data has been tampered with
        """
        chacha = ChaCha20Poly1305(key)
        plaintext = chacha.decrypt(nonce, ciphertext, None)
        return plaintext


class RSACipher:
    """RSA-OAEP for key encapsulation"""

    @staticmethod
    def generate_keypair(key_size: int = 4096) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """
        Generate RSA key pair

        Uses 4096-bit keys for quantum resistance.
        Public exponent 65537 is the standard choice.

        Args:
            key_size: Size of RSA key in bits (default: 4096)

        Returns:
            Tuple of (private_key, public_key)
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def encrypt(plaintext: bytes, public_key: rsa.RSAPublicKey) -> bytes:
        """
        Encrypt data using RSA-OAEP

        OAEP (Optimal Asymmetric Encryption Padding) provides semantic security.
        Uses SHA-256 for hashing.

        Note: RSA can only encrypt small amounts of data (less than key size).
        Use this for key encapsulation, not data encryption.

        Args:
            plaintext: Small data to encrypt (typically symmetric keys)
            public_key: RSA public key

        Returns:
            bytes: Encrypted data
        """
        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    @staticmethod
    def decrypt(ciphertext: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
        """
        Decrypt data using RSA-OAEP

        Args:
            ciphertext: Encrypted data
            private_key: RSA private key

        Returns:
            bytes: Decrypted plaintext
        """
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext

    @staticmethod
    def serialize_private_key(private_key: rsa.RSAPrivateKey) -> bytes:
        """
        Serialize private key to PEM format

        Args:
            private_key: RSA private key

        Returns:
            bytes: PEM-encoded private key
        """
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    @staticmethod
    def serialize_public_key(public_key: rsa.RSAPublicKey) -> bytes:
        """
        Serialize public key to PEM format

        Args:
            public_key: RSA public key

        Returns:
            bytes: PEM-encoded public key
        """
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def deserialize_private_key(pem_data: bytes) -> rsa.RSAPrivateKey:
        """
        Deserialize private key from PEM format

        Args:
            pem_data: PEM-encoded private key

        Returns:
            RSAPrivateKey object
        """
        return serialization.load_pem_private_key(pem_data, password=None)

    @staticmethod
    def deserialize_public_key(pem_data: bytes) -> rsa.RSAPublicKey:
        """
        Deserialize public key from PEM format

        Args:
            pem_data: PEM-encoded public key

        Returns:
            RSAPublicKey object
        """
        return serialization.load_pem_public_key(pem_data)


class HMACGenerator:
    """HMAC-SHA256 for integrity verification"""

    @staticmethod
    def generate_key() -> bytes:
        """
        Generate a key for HMAC using Cascading Entropy Mixer

        Returns:
            bytes: 32-byte HMAC key
        """
        return _key_generator.generate_key(32)

    @staticmethod
    def compute(data: bytes, key: bytes) -> bytes:
        """
        Compute HMAC-SHA256 of data

        HMAC provides integrity verification - detects if data has been modified.

        Args:
            data: Data to authenticate
            key: HMAC key

        Returns:
            bytes: 32-byte HMAC tag
        """
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(data)
        return h.finalize()

    @staticmethod
    def verify(data: bytes, key: bytes, expected_hmac: bytes) -> bool:
        """
        Verify HMAC-SHA256 of data

        Uses constant-time comparison to prevent timing attacks.

        Args:
            data: Data to verify
            key: HMAC key
            expected_hmac: Expected HMAC value

        Returns:
            bool: True if HMAC is valid, False otherwise
        """
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(data)
        try:
            h.verify(expected_hmac)
            return True
        except Exception:
            return False


class AES128GCMCipher:
    """AES-128-GCM encryption/decryption (128-bit key variant)"""

    @staticmethod
    def generate_key() -> bytes:
        """
        Generate a 128-bit (16 bytes) AES key using Cascading Entropy Mixer

        Returns:
            bytes: 16-byte AES key
        """
        return _key_generator.generate_key(16)  # 128 bits

    @staticmethod
    def generate_iv() -> bytes:
        """
        Generate a 96-bit (12 bytes) IV using os.urandom for guaranteed uniqueness

        Returns:
            bytes: 12-byte IV
        """
        # Use os.urandom directly for IVs to guarantee uniqueness
        return os.urandom(12)

    @staticmethod
    def encrypt(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt plaintext using AES-128-GCM

        Args:
            plaintext: Data to encrypt
            key: 16-byte AES key

        Returns:
            Tuple of (ciphertext, iv)
        """
        aesgcm = AESGCM(key)
        iv = os.urandom(12)  # 96 bits - MUST be unique
        ciphertext = aesgcm.encrypt(iv, plaintext, None)
        return ciphertext, iv

    @staticmethod
    def decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        """
        Decrypt ciphertext using AES-128-GCM

        Args:
            ciphertext: Encrypted data
            key: 16-byte AES key
            iv: 12-byte initialization vector

        Returns:
            bytes: Decrypted plaintext
        """
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(iv, ciphertext, None)
        return plaintext


class AESCBCCipher:
    """AES-256-CBC with PKCS7 padding (traditional block cipher mode)"""

    @staticmethod
    def generate_key() -> bytes:
        """
        Generate a 256-bit (32 bytes) AES key using Cascading Entropy Mixer

        Returns:
            bytes: 32-byte AES key
        """
        return _key_generator.generate_key(32)

    @staticmethod
    def generate_iv() -> bytes:
        """
        Generate a 128-bit (16 bytes) IV using os.urandom for guaranteed uniqueness

        Returns:
            bytes: 16-byte IV
        """
        # Use os.urandom directly for IVs to guarantee uniqueness
        return os.urandom(16)

    @staticmethod
    def encrypt(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt plaintext using AES-256-CBC with PKCS7 padding

        Note: CBC mode doesn't provide authentication by itself.
        We rely on the outer HMAC for integrity.

        Args:
            plaintext: Data to encrypt
            key: 32-byte AES key

        Returns:
            Tuple of (ciphertext, iv, auth_tag_placeholder)
            Note: auth_tag is empty bytes for CBC (authentication via HMAC)
        """
        # Apply PKCS7 padding
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        # Generate IV using os.urandom for uniqueness
        iv = os.urandom(16)  # 128 bits for CBC

        # Encrypt
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # CBC doesn't have auth tag, return empty bytes
        return ciphertext, iv, b''

    @staticmethod
    def decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        """
        Decrypt ciphertext using AES-256-CBC and remove PKCS7 padding

        Args:
            ciphertext: Encrypted data
            key: 32-byte AES key
            iv: 16-byte initialization vector

        Returns:
            bytes: Decrypted plaintext
        """
        # Decrypt
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove PKCS7 padding
        unpadder = sym_padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()

        return plaintext


class DESCipher:
    """DES encryption/decryption (56-bit key - INSECURE, academic use only)"""

    @staticmethod
    def generate_key() -> bytes:
        """
        Generate an 8-byte DES key (56-bit effective) using Cascading Entropy Mixer

        WARNING: DES is cryptographically broken. Use for academic purposes only.

        Returns:
            bytes: 8-byte DES key
        """
        return _key_generator.generate_key(8)  # DES uses 8-byte keys (56-bit effective)

    @staticmethod
    def generate_iv() -> bytes:
        """
        Generate an 8-byte IV for DES using os.urandom for guaranteed uniqueness

        Returns:
            bytes: 8-byte IV
        """
        # Use os.urandom directly for IVs to guarantee uniqueness
        return os.urandom(8)

    @staticmethod
    def encrypt(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt plaintext using DES in CBC mode with PKCS7 padding

        WARNING: DES is vulnerable to brute force attacks!

        Args:
            plaintext: Data to encrypt
            key: 8-byte DES key

        Returns:
            Tuple of (ciphertext, iv, empty_auth_tag)
            Note: DES-CBC doesn't have an auth tag (authentication via HMAC)
        """
        # Ensure key is exactly 8 bytes
        if len(key) > 8:
            key = key[:8]
        elif len(key) < 8:
            key = key.ljust(8, b'\0')

        # Apply PKCS7 padding (DES block size is 64 bits / 8 bytes)
        padder = sym_padding.PKCS7(64).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        # Generate IV using os.urandom for uniqueness (8 bytes for DES)
        iv = os.urandom(8)

        # Encrypt using DES in CBC mode
        # Use TripleDES with single DES key (backward compatibility)
        from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
        # For single DES, we need to use TripleDES with the key repeated 3 times
        triple_key = key + key + key  # 24 bytes for TripleDES
        cipher = Cipher(
            TripleDES(triple_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # Return format compatible with other ciphers (empty auth tag for CBC)
        return ciphertext, iv, b''

    @staticmethod
    def decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        """
        Decrypt ciphertext using DES in CBC mode

        Args:
            ciphertext: Encrypted data
            key: 8-byte DES key
            iv: 8-byte initialization vector

        Returns:
            bytes: Decrypted plaintext
        """
        # Ensure key is exactly 8 bytes
        if len(key) > 8:
            key = key[:8]
        elif len(key) < 8:
            key = key.ljust(8, b'\0')

        # Decrypt using DES in CBC mode
        # Use TripleDES with single DES key (backward compatibility)
        from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
        # For single DES, we need to use TripleDES with the key repeated 3 times
        triple_key = key + key + key  # 24 bytes for TripleDES
        cipher = Cipher(
            TripleDES(triple_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove PKCS7 padding
        unpadder = sym_padding.PKCS7(64).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()

        return plaintext


# Export all cipher classes
__all__ = [
    'AESGCMCipher',
    'AES128GCMCipher',
    'AESCBCCipher',
    'ChaCha20Cipher',
    'DESCipher',
    'RSACipher',
    'HMACGenerator'
]
