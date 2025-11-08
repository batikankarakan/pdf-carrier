"""
Key Management Module

Handles generation, storage, and retrieval of cryptographic keys.
Implements secure key file format for distribution.
"""

import json
import uuid
from datetime import datetime
from typing import Dict, Tuple
from .algorithms import AESGCMCipher, ChaCha20Cipher, RSACipher


def generate_encryption_keys() -> Dict:
    """
    Generate all keys needed for encryption

    Returns:
        Dict containing all generated keys:
        - aes_key: AES-256 symmetric key
        - chacha_key: ChaCha20 symmetric key
        - rsa_private: RSA private key
        - rsa_public: RSA public key
        - hmac_key: HMAC key for integrity
    """
    # Generate symmetric keys
    aes_key = AESGCMCipher.generate_key()
    chacha_key = ChaCha20Cipher.generate_key()

    # Generate RSA keypair
    rsa_private, rsa_public = RSACipher.generate_keypair(key_size=4096)

    return {
        'aes_key': aes_key,
        'chacha_key': chacha_key,
        'rsa_private': rsa_private,
        'rsa_public': rsa_public
    }


def create_key_file(private_key, public_key, algorithms: list) -> bytes:
    """
    Create a key file in JSON format for distribution

    This file contains the private key needed for decryption.
    It should be kept secure and distributed separately from the encrypted file.

    Args:
        private_key: RSA private key
        public_key: RSA public key
        algorithms: List of algorithm names used

    Returns:
        bytes: JSON-encoded key file
    """
    key_file_data = {
        "version": "1.0",
        "key_type": "RSA_PRIVATE",
        "private_key_pem": RSACipher.serialize_private_key(private_key).decode('utf-8'),
        "public_key_pem": RSACipher.serialize_public_key(public_key).decode('utf-8'),
        "key_size": 4096,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "key_id": str(uuid.uuid4()),
        "algorithm_pool": algorithms
    }

    return json.dumps(key_file_data, indent=2).encode('utf-8')


def load_key_file(key_file_bytes: bytes) -> Dict:
    """
    Load and parse a key file

    Args:
        key_file_bytes: Key file content

    Returns:
        Dict containing:
        - private_key: RSA private key object
        - public_key: RSA public key object
        - metadata: Additional key file information

    Raises:
        ValueError: If key file format is invalid
    """
    try:
        key_file_data = json.loads(key_file_bytes.decode('utf-8'))

        # Validate key file version
        if key_file_data.get('version') != '1.0':
            raise ValueError("Unsupported key file version")

        # Deserialize keys
        private_key = RSACipher.deserialize_private_key(
            key_file_data['private_key_pem'].encode('utf-8')
        )
        public_key = RSACipher.deserialize_public_key(
            key_file_data['public_key_pem'].encode('utf-8')
        )

        return {
            'private_key': private_key,
            'public_key': public_key,
            'metadata': {
                'key_id': key_file_data.get('key_id'),
                'created_at': key_file_data.get('created_at'),
                'algorithm_pool': key_file_data.get('algorithm_pool', [])
            }
        }

    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid key file format: {e}")
    except KeyError as e:
        raise ValueError(f"Missing required key file field: {e}")


def encapsulate_symmetric_keys(aes_key: bytes, chacha_key: bytes, public_key) -> bytes:
    """
    Encrypt symmetric keys using RSA public key

    This implements hybrid encryption:
    - Symmetric keys encrypt the data (fast)
    - RSA encrypts the symmetric keys (secure key distribution)

    Args:
        aes_key: AES symmetric key
        chacha_key: ChaCha20 symmetric key
        public_key: RSA public key

    Returns:
        bytes: Encrypted symmetric keys bundle
    """
    # Bundle symmetric keys together
    keys_bundle = json.dumps({
        'aes_key': aes_key.hex(),
        'chacha_key': chacha_key.hex()
    }).encode('utf-8')

    # Encrypt bundle with RSA
    encrypted_keys = RSACipher.encrypt(keys_bundle, public_key)

    return encrypted_keys


def decapsulate_symmetric_keys(encrypted_keys: bytes, private_key) -> Tuple[bytes, bytes]:
    """
    Decrypt symmetric keys using RSA private key

    Args:
        encrypted_keys: Encrypted keys bundle
        private_key: RSA private key

    Returns:
        Tuple of (aes_key, chacha_key)

    Raises:
        ValueError: If key bundle format is invalid
    """
    try:
        # Decrypt bundle with RSA
        keys_bundle = RSACipher.decrypt(encrypted_keys, private_key)

        # Parse bundle
        keys_data = json.loads(keys_bundle.decode('utf-8'))

        aes_key = bytes.fromhex(keys_data['aes_key'])
        chacha_key = bytes.fromhex(keys_data['chacha_key'])

        return aes_key, chacha_key

    except (json.JSONDecodeError, KeyError) as e:
        raise ValueError(f"Invalid encrypted keys format: {e}")


__all__ = [
    'generate_encryption_keys',
    'create_key_file',
    'load_key_file',
    'encapsulate_symmetric_keys',
    'decapsulate_symmetric_keys'
]
