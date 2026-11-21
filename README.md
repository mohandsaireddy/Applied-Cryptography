# Applied-Cryptography
AES-256 based Secure Backup and Recovery System

An enterprise-grade backup and recovery platform developed in Python using **AES-256-GCM**, **scrypt Key Derivation (KDF)**, **zlib data compression**, **SQLite**, and a **Flask Web Interface**.

---

## 🎯 Project Objectives & Task Compliance

| Task | Objective | Implementation in System |
| :--- | :--- | :--- |
| **Task 1: Backup Encryption & Cryptography** | Encrypt backup files using AES-256 before storing them. | **AES-256-GCM** Authenticated Encryption with Associated Data (AEAD). Unique 16-byte random salt and 12-byte nonce per backup. Keys derived dynamically from user password via **`scrypt`**. |
| **Task 2: Secure Backup Recovery** | Restore encrypted backups only after successful user authentication. | Zero-knowledge decryption: User must authenticate and re-verify their master password to derive the recovery key. Decryption is authenticated via 128-bit MAC tag. |
| **Task 3: Performance Evaluation** | Measure backup creation time, recovery time, and storage efficiency. | **Performance Evaluation Dashboard**: tracks real-time execution latency (ms), storage efficiency (% saved), and recovery throughput across user backups. |

---

## 🔐 Cryptographic Architecture

### 1. Key Derivation Function (KDF): `scrypt`
- **Memory-Hard Security:** `scrypt` is memory-hard ($N=16384, r=8, p=1$). It requires significant RAM during computation, neutralizing high-speed hardware brute-force attacks via ASICs and GPUs.
- Each backup generates an independent cryptographic 16-byte random salt, ensuring identical files encrypted with the same password yield completely unique ciphertexts.

### 2. Encryption Algorithm: AES-256-GCM
- **Galois/Counter Mode (GCM)** provides **Authenticated Encryption with Associated Data (AEAD)**.
- Combines AES counter-mode confidentiality with a Galois MAC authentication tag.
- Guarantees that ciphertext cannot be altered or corrupted without triggering an immediate cryptographic failure during decryption (`MAC check failed`).

### 3. Compress-then-Encrypt Pipeline
- Encrypted data exhibits maximum entropy and cannot be compressed.
- Applying **`zlib` compression prior to encryption** optimizes storage efficiency, reducing backup footprint and transfer latency.

### 4. Dual-Layer Integrity Verification
1. **Layer 1:** AES-256-GCM 16-byte MAC authentication tag (detects in-transit tampering).
2. **Layer 2:** End-to-end original file SHA-256 checksum verification after decompression.
   - The web dashboard allows users to **view the full 64-character SHA-256 checksum** in a modal as well as **one-click copy to clipboard**.

---

## 🗄️ Database Architecture (SQLite)

- **`users`**: User identities, scrypt authentication hashes, random auth salts, created timestamp.
- **`backups`**: Storage mapping, original/compressed/encrypted byte sizes, cryptographic salt, nonce, GCM tag, SHA-256 checksum, backup creation time (ms), and compression ratio.
- **`recovery_logs`**: Historical audit of recovery attempts, time taken (ms), and outcome (`SUCCESS`, `AUTH_FAILURE`, `INTEGRITY_FAILURE`).
- **`security_logs`**: Security audit trail recording login events, backup operations, and failed recovery attempts.

---

## 🚀 How to Run the System

### Prerequisites
- Python 3.10+
- Dependencies: `pycryptodome`, `flask`

### Quick Start (Windows)
1. Double-click **`run.bat`** (or open PowerShell in the project directory).
2. Or run via command line:
   ```powershell
   python app.py
   ```
3. Open your web browser and navigate to:
   ```
   http://127.0.0.1:5000
   ```

---

## 🖥️ Web Interface Features

1. **User Authentication (`/login` & `/register`)**:
   - Secure account registration with scrypt password hashing.
   - Zero-knowledge design: master encryption keys are never stored in the database.
2. **Backup Vault Dashboard (`/dashboard`)**:
   - Live metrics: Total Backups, Protected Data Volume, Storage Efficiency %, Avg Latency.
   - Drag-and-drop backup creator with master password confirmation and compression toggle.
   - Backups table with original vs encrypted sizes, SHA-256 fingerprints, and actions.
   - **View & Copy Full SHA-256 Checksum:** Inline copy button and dedicated modal displaying the full 64-character hash.
   - Instant file recovery modal with password authentication and direct file download.
   - Raw ciphertext download button (`.enc`) for cryptographic inspection.
3. **Performance Evaluation Tab (`/performance`)**:
   - Live evaluation metrics: Avg Backup Time, Avg Recovery Time, Storage Efficiency Saved (%), and Successful Restores.
   - Real User Backup Latency Log: records file names, sizes, compression savings, and execution time (ms).
   - Recovery Performance Log: tracks restore latency and cryptographic MAC verification status.
4. **Audit Trail (`/audit-logs`)**:
   - Complete record of cryptographic activities, client IP addresses, and timestamps.
