import os

# Base paths
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
STORAGE_DIR = os.path.join(BASE_DIR, 'storage')
ENCRYPTED_DIR = os.path.join(STORAGE_DIR, 'encrypted')
TEMP_DIR = os.path.join(STORAGE_DIR, 'temp')
DATABASE_PATH = os.path.join(BASE_DIR, 'database.db')

# Ensure directories exist
os.makedirs(ENCRYPTED_DIR, exist_ok=True)
os.makedirs(TEMP_DIR, exist_ok=True)

# Application secret
SECRET_KEY = os.environ.get('SECRET_KEY', 'aes-backup-system-super-secret-key-2026')

# Cryptographic configuration
# scrypt parameters (RFC 7914 recommended for interactive login / key derivation)
SCRYPT_N = 16384       # CPU/memory cost parameter (2^14)
SCRYPT_R = 8           # Block size parameter
SCRYPT_P = 1           # Parallelization parameter
AES_KEY_BYTES = 32     # 256-bit AES key
SALT_BYTES = 16        # 128-bit cryptographic salt
GCM_NONCE_BYTES = 12   # Standard 96-bit nonce for AES-GCM
GCM_TAG_BYTES = 16     # 128-bit authentication tag

# Compression
COMPRESSION_LEVEL = 6  # Balanced speed and compression ratio (1-9)

# Maximum file upload size: 250 MB
MAX_CONTENT_LENGTH = 250 * 1024 * 1024
