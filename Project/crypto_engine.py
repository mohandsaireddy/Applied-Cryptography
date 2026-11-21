import os
import time
import zlib
import hashlib
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
import config

class CryptographicError(Exception):
    """Custom exception raised during cryptographic or integrity failures."""
    pass

class TamperDetectedError(CryptographicError):
    """Raised specifically when AES-GCM MAC verification fails due to tampering or wrong key."""
    pass

class IntegrityError(CryptographicError):
    """Raised when decompressed file SHA-256 checksum does not match original."""
    pass


def generate_salt(length=config.SALT_BYTES) -> bytes:
    """Generate cryptographically secure random bytes for salting."""
    return get_random_bytes(length)


def derive_aes_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit AES key from a user password and unique salt using scrypt.
    scrypt is memory-hard and significantly more resistant to GPU/ASIC hardware brute-force
    attacks than traditional PBKDF2 or SHA-based KDFs.
    """
    if isinstance(password, str):
        password = password.encode('utf-8')
    return scrypt(
        password=password,
        salt=salt,
        key_len=config.AES_KEY_BYTES,
        N=config.SCRYPT_N,
        r=config.SCRYPT_R,
        p=config.SCRYPT_P
    )


def hash_user_password(password: str) -> tuple[str, str]:
    """
    Hash a user password for database storage and authentication.
    Returns (salt_hex, hash_hex).
    """
    salt = generate_salt(config.SALT_BYTES)
    derived = derive_aes_key(password, salt)
    return salt.hex(), derived.hex()


def verify_user_password(password: str, salt_hex: str, expected_hash_hex: str) -> bool:
    """Verify an input password against stored salt and hash."""
    salt = bytes.fromhex(salt_hex)
    derived = derive_aes_key(password, salt)
    return derived.hex() == expected_hash_hex


def calculate_sha256(data: bytes) -> str:
    """Calculate the SHA-256 hash of raw data for end-to-end integrity checks."""
    return hashlib.sha256(data).hexdigest()


def encrypt_file_data(raw_data: bytes, password: str, enable_compression: bool = True) -> dict:
    """
    Full secure backup pipeline:
    1. Compute original SHA-256 checksum.
    2. Optional compression (zlib) - Compress before encrypting.
    3. Generate fresh 16-byte salt and 12-byte GCM nonce.
    4. Derive 256-bit AES key from password via scrypt.
    5. Encrypt with AES-256-GCM (confidentiality + authenticity).
    6. Measure backup creation time, storage sizes, and efficiency.
    """
    start_time = time.perf_counter()
    
    original_size = len(raw_data)
    checksum_sha256 = calculate_sha256(raw_data)

    # Step 1: Compression
    comp_start = time.perf_counter()
    if enable_compression and original_size > 0:
        compressed_data = zlib.compress(raw_data, level=config.COMPRESSION_LEVEL)
    else:
        compressed_data = raw_data
    compressed_size = len(compressed_data)
    comp_time_ms = (time.perf_counter() - comp_start) * 1000

    # Step 2: Key Derivation
    kdf_start = time.perf_counter()
    salt = generate_salt(config.SALT_BYTES)
    aes_key = derive_aes_key(password, salt)
    kdf_time_ms = (time.perf_counter() - kdf_start) * 1000

    # Step 3: AES-256-GCM Encryption
    enc_start = time.perf_counter()
    nonce = get_random_bytes(config.GCM_NONCE_BYTES)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, auth_tag = cipher.encrypt_and_digest(compressed_data)
    enc_time_ms = (time.perf_counter() - enc_start) * 1000

    total_time_ms = (time.perf_counter() - start_time) * 1000
    encrypted_size = len(ciphertext)

    # Storage efficiency calculation
    if original_size > 0:
        compression_ratio = ((original_size - compressed_size) / original_size) * 100
        overall_storage_efficiency = ((original_size - encrypted_size) / original_size) * 100
    else:
        compression_ratio = 0.0
        overall_storage_efficiency = 0.0

    throughput_mb_s = (original_size / (1024 * 1024)) / (total_time_ms / 1000) if total_time_ms > 0 else 0.0

    return {
        'ciphertext': ciphertext,
        'salt_hex': salt.hex(),
        'nonce_hex': nonce.hex(),
        'tag_hex': auth_tag.hex(),
        'checksum_sha256': checksum_sha256,
        'is_compressed': enable_compression,
        'original_size': original_size,
        'compressed_size': compressed_size,
        'encrypted_size': encrypted_size,
        'compression_ratio': round(compression_ratio, 2),
        'storage_efficiency': round(overall_storage_efficiency, 2),
        'backup_time_ms': round(total_time_ms, 2),
        'kdf_time_ms': round(kdf_time_ms, 2),
        'enc_time_ms': round(enc_time_ms, 2),
        'comp_time_ms': round(comp_time_ms, 2),
        'throughput_mb_s': round(throughput_mb_s, 2)
    }


def decrypt_file_data(
    ciphertext: bytes,
    password: str,
    salt_hex: str,
    nonce_hex: str,
    tag_hex: str,
    expected_checksum: str,
    is_compressed: bool = True
) -> tuple[bytes, dict]:
    """
    Full secure recovery pipeline:
    1. Derive 256-bit AES key from supplied password and stored salt using scrypt.
    2. Re-initialize AES-256-GCM with stored nonce.
    3. Verify integrity & decrypt using stored 16-byte authentication tag.
       (If wrong password OR ciphertext is modified/corrupted, raises TamperDetectedError).
    4. Decompress with zlib (if compression was enabled).
    5. Verify SHA-256 checksum against expected original value.
    6. Return decrypted original bytes and recovery metrics.
    """
    start_time = time.perf_counter()

    salt = bytes.fromhex(salt_hex)
    nonce = bytes.fromhex(nonce_hex)
    auth_tag = bytes.fromhex(tag_hex)

    # Step 1: Key Derivation
    kdf_start = time.perf_counter()
    aes_key = derive_aes_key(password, salt)
    kdf_time_ms = (time.perf_counter() - kdf_start) * 1000

    # Step 2: AES-256-GCM Authenticated Decryption
    dec_start = time.perf_counter()
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    try:
        decrypted_compressed = cipher.decrypt_and_verify(ciphertext, auth_tag)
    except ValueError as e:
        # PyCryptodome raises ValueError("MAC check failed") when auth_tag check fails
        raise TamperDetectedError(
            "Cryptographic Authentication Failed! Either the recovery password is incorrect, "
            "or the backup file has been corrupted or tampered with."
        ) from e
    dec_time_ms = (time.perf_counter() - dec_start) * 1000

    # Step 3: Decompression
    decomp_start = time.perf_counter()
    if is_compressed:
        try:
            restored_data = zlib.decompress(decrypted_compressed)
        except Exception as e:
            raise IntegrityError(f"Decompression failed: {str(e)}") from e
    else:
        restored_data = decrypted_compressed
    decomp_time_ms = (time.perf_counter() - decomp_start) * 1000

    # Step 4: End-to-end Checksum Verification
    actual_checksum = calculate_sha256(restored_data)
    if actual_checksum != expected_checksum:
        raise IntegrityError(
            f"Data integrity mismatch! Expected SHA-256: {expected_checksum}, got: {actual_checksum}"
        )

    total_recovery_time_ms = (time.perf_counter() - start_time) * 1000
    throughput_mb_s = (len(restored_data) / (1024 * 1024)) / (total_recovery_time_ms / 1000) if total_recovery_time_ms > 0 else 0.0

    metrics = {
        'recovery_time_ms': round(total_recovery_time_ms, 2),
        'kdf_time_ms': round(kdf_time_ms, 2),
        'dec_time_ms': round(dec_time_ms, 2),
        'decomp_time_ms': round(decomp_time_ms, 2),
        'restored_size': len(restored_data),
        'throughput_mb_s': round(throughput_mb_s, 2),
        'checksum_verified': True
    }

    return restored_data, metrics
