import sqlite3
import os
import config

def get_db_connection():
    """Establish a connection to the SQLite database with dictionary cursor."""
    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    # Enable foreign keys
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def _setup_tables():
    """Internal helper to create all tables and indexes."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            auth_salt TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Backups table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS backups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            original_filename TEXT NOT NULL,
            encrypted_filename TEXT NOT NULL,
            original_size INTEGER NOT NULL,
            compressed_size INTEGER NOT NULL,
            encrypted_size INTEGER NOT NULL,
            salt_hex TEXT NOT NULL,
            nonce_hex TEXT NOT NULL,
            tag_hex TEXT NOT NULL,
            checksum_sha256 TEXT NOT NULL,
            is_compressed INTEGER DEFAULT 1,
            backup_time_ms REAL NOT NULL,
            compression_ratio REAL NOT NULL,
            storage_efficiency REAL NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    # Recovery logs table (Performance & History)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS recovery_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            backup_id INTEGER,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            recovery_time_ms REAL NOT NULL,
            status TEXT NOT NULL,
            error_message TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    # Security audit logs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            event_type TEXT NOT NULL,
            details TEXT NOT NULL,
            status TEXT NOT NULL,
            ip_address TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Create helpful indexes
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_backups_user ON backups(user_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_recovery_user ON recovery_logs(user_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_security_event ON security_logs(event_type)')

    conn.commit()
    conn.close()

def init_db():
    """Initialize database tables and indexes with auto-recovery from corrupted disk images."""
    try:
        _setup_tables()
    except sqlite3.DatabaseError as e:
        print(f"[DATABASE WARNING] Corrupted or malformed database file detected: {e}")
        print("[DATABASE RECOVERY] Resetting database to a clean, pristine state...")
        try:
            if os.path.exists(config.DATABASE_PATH):
                os.remove(config.DATABASE_PATH)
        except OSError:
            pass
        _setup_tables()
        print("[DATABASE RECOVERY] Clean database created successfully.")


# --- User Operations ---

def create_user(username: str, password_hash: str, auth_salt: str, role: str = 'user') -> int:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO users (username, password_hash, auth_salt, role) VALUES (?, ?, ?, ?)',
        (username.strip(), password_hash, auth_salt, role)
    )
    user_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return user_id

def get_user_by_username(username: str):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ? COLLATE NOCASE', (username.strip(),)).fetchone()
    conn.close()
    return user

def get_user_by_id(user_id: int):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    return user

# --- Backup Operations ---

def save_backup_record(
    user_id: int,
    original_filename: str,
    encrypted_filename: str,
    original_size: int,
    compressed_size: int,
    encrypted_size: int,
    salt_hex: str,
    nonce_hex: str,
    tag_hex: str,
    checksum_sha256: str,
    is_compressed: bool,
    backup_time_ms: float,
    compression_ratio: float,
    storage_efficiency: float
) -> int:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO backups (
            user_id, original_filename, encrypted_filename,
            original_size, compressed_size, encrypted_size,
            salt_hex, nonce_hex, tag_hex, checksum_sha256,
            is_compressed, backup_time_ms, compression_ratio, storage_efficiency
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        user_id, original_filename, encrypted_filename,
        original_size, compressed_size, encrypted_size,
        salt_hex, nonce_hex, tag_hex, checksum_sha256,
        1 if is_compressed else 0,
        backup_time_ms, compression_ratio, storage_efficiency
    ))
    backup_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return backup_id

def get_backups_for_user(user_id: int):
    conn = get_db_connection()
    backups = conn.execute(
        'SELECT * FROM backups WHERE user_id = ? ORDER BY created_at DESC',
        (user_id,)
    ).fetchall()
    conn.close()
    return backups

def get_backup_by_id(backup_id: int, user_id: int = None):
    conn = get_db_connection()
    if user_id is not None:
        backup = conn.execute(
            'SELECT * FROM backups WHERE id = ? AND user_id = ?',
            (backup_id, user_id)
        ).fetchone()
    else:
        backup = conn.execute('SELECT * FROM backups WHERE id = ?', (backup_id,)).fetchone()
    conn.close()
    return backup

def delete_backup_record(backup_id: int, user_id: int) -> bool:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM backups WHERE id = ? AND user_id = ?', (backup_id, user_id))
    affected = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return affected

# --- Logging & Analytics Operations ---

def log_recovery(backup_id: int, user_id: int, filename: str, recovery_time_ms: float, status: str, error_message: str = None):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO recovery_logs (backup_id, user_id, filename, recovery_time_ms, status, error_message)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (backup_id, user_id, filename, recovery_time_ms, status, error_message))
    conn.commit()
    conn.close()

def log_security_event(user_id: int, username: str, event_type: str, details: str, status: str, ip_address: str = None):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO security_logs (user_id, username, event_type, details, status, ip_address)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (user_id, username, event_type, details, status, ip_address))
    conn.commit()
    conn.close()

def get_security_logs(limit: int = 50, user_id: int = None):
    conn = get_db_connection()
    if user_id:
        logs = conn.execute(
            'SELECT * FROM security_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT ?',
            (user_id, limit)
        ).fetchall()
    else:
        logs = conn.execute(
            'SELECT * FROM security_logs ORDER BY created_at DESC LIMIT ?',
            (limit,)
        ).fetchall()
    conn.close()
    return logs

def get_performance_stats(user_id: int = None):
    conn = get_db_connection()
    params = [user_id] if user_id else []
    where_user = "WHERE user_id = ?" if user_id else ""

    summary = conn.execute(f'''
        SELECT 
            COUNT(*) as total_backups,
            COALESCE(SUM(original_size), 0) as total_orig_bytes,
            COALESCE(SUM(encrypted_size), 0) as total_enc_bytes,
            COALESCE(AVG(backup_time_ms), 0) as avg_backup_time,
            COALESCE(AVG(compression_ratio), 0) as avg_compression_ratio,
            COALESCE(AVG(storage_efficiency), 0) as avg_storage_efficiency
        FROM backups {where_user}
    ''', params).fetchone()

    recovery_summary = conn.execute(f'''
        SELECT 
            COUNT(*) as total_recoveries,
            COALESCE(AVG(recovery_time_ms), 0) as avg_recovery_time,
            SUM(CASE WHEN status = 'SUCCESS' THEN 1 ELSE 0 END) as successful_recoveries,
            SUM(CASE WHEN status != 'SUCCESS' THEN 1 ELSE 0 END) as failed_recoveries
        FROM recovery_logs {where_user}
    ''', params).fetchone()

    conn.close()
    return dict(summary), dict(recovery_summary)

def get_recovery_logs_for_user(user_id: int, limit: int = 15):
    conn = get_db_connection()
    logs = conn.execute(
        'SELECT * FROM recovery_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT ?',
        (user_id, limit)
    ).fetchall()
    conn.close()
    return logs

