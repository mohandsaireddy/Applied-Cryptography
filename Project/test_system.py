import os
import database
import crypto_engine

def run_integration_tests():
    print("=" * 65)
    print("  AES Secure Backup & Recovery - Automated Integration Test")
    print("=" * 65)

    # 1. Database Initialization
    print("[1/6] Initializing SQLite database...")
    database.init_db()
    print("      ✓ Tables created and verified.")

    # 2. User Authentication & scrypt Key Derivation
    print("[2/6] Testing User Registration & Password Verification...")
    test_user = "test_evaluator"
    test_pass = "SecureMasterPassword#2026"
    
    salt_hex, hash_hex = crypto_engine.hash_user_password(test_pass)
    assert crypto_engine.verify_user_password(test_pass, salt_hex, hash_hex) is True, "Password verification failed"
    assert crypto_engine.verify_user_password("WrongPassword!", salt_hex, hash_hex) is False, "Wrong password accepted"
    
    # Save or retrieve user
    existing = database.get_user_by_username(test_user)
    if not existing:
        user_id = database.create_user(test_user, hash_hex, salt_hex)
    else:
        user_id = existing['id']
    print(f"      ✓ User '{test_user}' authenticated (ID: {user_id}) using memory-hard scrypt KDF.")

    # 3. Compress & Encrypt (AES-256-GCM)
    print("[3/6] Testing Compress-then-Encrypt Pipeline...")
    sample_content = b"Confidential Project Data: AES-256-GCM protects both confidentiality and integrity.\n" * 50
    enc_result = crypto_engine.encrypt_file_data(sample_content, test_pass, enable_compression=True)
    
    orig_len = enc_result['original_size']
    enc_len = enc_result['encrypted_size']
    ratio = enc_result['compression_ratio']
    print(f"      ✓ Original: {orig_len} B -> Encrypted: {enc_len} B (Compression ratio: {ratio}%)")
    print(f"      ✓ Backup Latency: {enc_result['backup_time_ms']} ms (Throughput: {enc_result['throughput_mb_s']} MB/s)")
    print(f"      ✓ Full SHA-256 Checksum: {enc_result['checksum_sha256']}")

    # 4. Decrypt & Restore (AES-256-GCM + Decompression)
    print("[4/6] Testing Decrypt-then-Decompress Pipeline...")
    restored_bytes, rec_metrics = crypto_engine.decrypt_file_data(
        ciphertext=enc_result['ciphertext'],
        password=test_pass,
        salt_hex=enc_result['salt_hex'],
        nonce_hex=enc_result['nonce_hex'],
        tag_hex=enc_result['tag_hex'],
        expected_checksum=enc_result['checksum_sha256'],
        is_compressed=True
    )
    assert restored_bytes == sample_content, "Restored content does not match original!"
    print(f"      ✓ Payload restored byte-for-byte in {rec_metrics['recovery_time_ms']} ms.")
    print("      ✓ SHA-256 Checksum verified: PASS")

    # 5. Security & Tamper Rejection (Task 4)
    print("[5/6] Testing Tamper Resistance & Invalid Password Rejection...")
    # Corrupt a byte in ciphertext
    corrupted = bytearray(enc_result['ciphertext'])
    corrupted[5] ^= 0xFF
    try:
        crypto_engine.decrypt_file_data(
            ciphertext=bytes(corrupted),
            password=test_pass,
            salt_hex=enc_result['salt_hex'],
            nonce_hex=enc_result['nonce_hex'],
            tag_hex=enc_result['tag_hex'],
            expected_checksum=enc_result['checksum_sha256'],
            is_compressed=True
        )
        assert False, "Tampered ciphertext was not detected!"
    except crypto_engine.TamperDetectedError:
        print("      ✓ Data corruption successfully detected via AES-GCM MAC check: PASS")

    try:
        crypto_engine.decrypt_file_data(
            ciphertext=enc_result['ciphertext'],
            password="WrongPassword123",
            salt_hex=enc_result['salt_hex'],
            nonce_hex=enc_result['nonce_hex'],
            tag_hex=enc_result['tag_hex'],
            expected_checksum=enc_result['checksum_sha256'],
            is_compressed=True
        )
        assert False, "Unauthorized password decrypted file!"
    except crypto_engine.TamperDetectedError:
        print("      ✓ Unauthorized password decryption blocked: PASS")

    # 6. Performance Evaluation & Logging (Task 3)
    print("[6/6] Verifying Performance Metrics & Recovery Logging...")
    backup_id = database.save_backup_record(
        user_id=user_id,
        original_filename="test_integration.bin",
        encrypted_filename="test_integration.enc",
        original_size=orig_len,
        compressed_size=enc_result['compressed_size'],
        encrypted_size=enc_len,
        salt_hex=enc_result['salt_hex'],
        nonce_hex=enc_result['nonce_hex'],
        tag_hex=enc_result['tag_hex'],
        checksum_sha256=enc_result['checksum_sha256'],
        is_compressed=True,
        backup_time_ms=enc_result['backup_time_ms'],
        compression_ratio=ratio,
        storage_efficiency=enc_result['storage_efficiency']
    )
    database.log_recovery(backup_id, user_id, "test_integration.bin", rec_metrics['recovery_time_ms'], "SUCCESS")
    summary, rec_summary = database.get_performance_stats(user_id)
    print(f"      ✓ Total Backups Evaluated: {summary['total_backups']}")
    print(f"      ✓ Avg Backup Creation Latency: {round(summary['avg_backup_time'], 2)} ms")
    print(f"      ✓ Avg Recovery Latency: {round(rec_summary['avg_recovery_time'], 2)} ms")
    print(f"      ✓ Avg Storage Efficiency Saved: {round(summary['avg_storage_efficiency'], 2)}%")

    print("\n" + "=" * 65)
    print("  ALL 6 INTEGRATION CHECKS PASSED SUCCESSFULLY (100%)")
    print("=" * 65)

if __name__ == '__main__':
    run_integration_tests()
