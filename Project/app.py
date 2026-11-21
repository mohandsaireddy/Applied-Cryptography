import os
import uuid
import io
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, jsonify, send_file, make_response
)
from werkzeug.utils import secure_filename

import config
import database
import crypto_engine

app = Flask(__name__)
app.config['SECRET_KEY'] = config.SECRET_KEY
app.config['MAX_CONTENT_LENGTH'] = config.MAX_CONTENT_LENGTH

# Initialize database tables on startup
database.init_db()


def login_required(f):
    """Decorator to protect routes requiring authentication."""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# ---------------------------------------------------------------------
# Authentication Routes
# ---------------------------------------------------------------------

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        client_ip = request.remote_addr

        if not username or not password:
            flash('Both username and password are required.', 'danger')
            return render_template('login.html')

        user = database.get_user_by_username(username)
        if user and crypto_engine.verify_user_password(password, user['auth_salt'], user['password_hash']):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            database.log_security_event(user['id'], user['username'], 'USER_LOGIN', 'User logged in successfully', 'SUCCESS', client_ip)
            flash(f'Welcome back, {user["username"]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            database.log_security_event(None, username, 'AUTH_FAILURE', 'Invalid login credentials entered', 'FAILURE', client_ip)
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        client_ip = request.remote_addr

        if not username or not password:
            flash('All fields are required.', 'danger')
            return render_template('register.html')

        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'warning')
            return render_template('register.html')

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html')

        existing_user = database.get_user_by_username(username)
        if existing_user:
            flash('Username is already taken. Please choose another.', 'warning')
            return render_template('register.html')

        salt_hex, hash_hex = crypto_engine.hash_user_password(password)
        user_id = database.create_user(username, hash_hex, salt_hex)
        database.log_security_event(user_id, username, 'USER_REGISTER', 'New account registered', 'SUCCESS', client_ip)

        flash('Registration successful! You may now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/logout')
def logout():
    username = session.get('username', 'Unknown')
    user_id = session.get('user_id')
    database.log_security_event(user_id, username, 'USER_LOGOUT', 'User logged out', 'SUCCESS', request.remote_addr)
    session.clear()
    flash('You have been logged out safely.', 'info')
    return redirect(url_for('login'))


# ---------------------------------------------------------------------
# Dashboard & Backup Management
# ---------------------------------------------------------------------

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']
    backups = database.get_backups_for_user(user_id)
    summary, rec_summary = database.get_performance_stats(user_id)
    return render_template('dashboard.html', backups=backups, summary=summary, rec_summary=rec_summary)


@app.route('/api/backup', methods=['POST'])
@login_required
def create_backup():
    user_id = session['user_id']
    username = session['username']
    client_ip = request.remote_addr

    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file uploaded.'}), 400

    uploaded_file = request.files['file']
    password = request.form.get('password', '')
    enable_compression = request.form.get('compression', 'true').lower() == 'true'

    if not uploaded_file or uploaded_file.filename == '':
        return jsonify({'success': False, 'message': 'No selected file.'}), 400

    if not password:
        return jsonify({'success': False, 'message': 'Password is required to derive AES key.'}), 400

    # Verify password belongs to current user to prevent key mismatch
    current_user = database.get_user_by_id(user_id)
    if not crypto_engine.verify_user_password(password, current_user['auth_salt'], current_user['password_hash']):
        database.log_security_event(user_id, username, 'BACKUP_AUTH_FAIL', 'Incorrect account password during backup attempt', 'FAILURE', client_ip)
        return jsonify({'success': False, 'message': 'Incorrect password! Key derivation aborted.'}), 403

    original_filename = secure_filename(uploaded_file.filename) or 'backup_file.bin'
    raw_data = uploaded_file.read()

    try:
        # Perform compression and AES-256-GCM encryption with scrypt key derivation
        enc_res = crypto_engine.encrypt_file_data(raw_data, password, enable_compression=enable_compression)

        # Generate unique storage filename
        stored_filename = f"{uuid.uuid4().hex}.enc"
        stored_path = os.path.join(config.ENCRYPTED_DIR, stored_filename)

        # Write ciphertext to disk
        with open(stored_path, 'wb') as f:
            f.write(enc_res['ciphertext'])

        # Record in SQLite database
        backup_id = database.save_backup_record(
            user_id=user_id,
            original_filename=original_filename,
            encrypted_filename=stored_filename,
            original_size=enc_res['original_size'],
            compressed_size=enc_res['compressed_size'],
            encrypted_size=enc_res['encrypted_size'],
            salt_hex=enc_res['salt_hex'],
            nonce_hex=enc_res['nonce_hex'],
            tag_hex=enc_res['tag_hex'],
            checksum_sha256=enc_res['checksum_sha256'],
            is_compressed=enc_res['is_compressed'],
            backup_time_ms=enc_res['backup_time_ms'],
            compression_ratio=enc_res['compression_ratio'],
            storage_efficiency=enc_res['storage_efficiency']
        )

        database.log_security_event(
            user_id, username, 'BACKUP_CREATED',
            f"Created backup #{backup_id} for '{original_filename}' (Orig: {enc_res['original_size']} B, Enc: {enc_res['encrypted_size']} B)",
            'SUCCESS', client_ip
        )

        return jsonify({
            'success': True,
            'message': f"Backup created successfully in {enc_res['backup_time_ms']} ms!",
            'metrics': {
                'backup_id': backup_id,
                'original_filename': original_filename,
                'original_size': enc_res['original_size'],
                'compressed_size': enc_res['compressed_size'],
                'encrypted_size': enc_res['encrypted_size'],
                'compression_ratio': enc_res['compression_ratio'],
                'storage_efficiency': enc_res['storage_efficiency'],
                'backup_time_ms': enc_res['backup_time_ms'],
                'throughput_mb_s': enc_res['throughput_mb_s'],
                'sha256': enc_res['checksum_sha256']
            }
        })

    except Exception as e:
        database.log_security_event(user_id, username, 'BACKUP_ERROR', f"Backup failed: {str(e)}", 'FAILURE', client_ip)
        return jsonify({'success': False, 'message': f"Encryption error: {str(e)}"}), 500


@app.route('/api/recover/<int:backup_id>', methods=['POST'])
@login_required
def recover_backup(backup_id):
    user_id = session['user_id']
    username = session['username']
    client_ip = request.remote_addr
    password = request.form.get('password', '')

    if not password:
        return jsonify({'success': False, 'message': 'Password required for decryption key derivation.'}), 400

    # Verify authorization & get backup record
    backup = database.get_backup_by_id(backup_id, user_id=user_id)
    if not backup:
        database.log_security_event(user_id, username, 'UNAUTHORIZED_RECOVERY_ATTEMPT', f"Attempted to access backup ID {backup_id}", 'SECURITY_ALERT', client_ip)
        return jsonify({'success': False, 'message': 'Backup not found or access denied.'}), 404

    stored_path = os.path.join(config.ENCRYPTED_DIR, backup['encrypted_filename'])
    if not os.path.exists(stored_path):
        return jsonify({'success': False, 'message': 'Encrypted file not found on disk.'}), 404

    with open(stored_path, 'rb') as f:
        ciphertext = f.read()

    try:
        # Perform scrypt key derivation + AES-256-GCM verification + decompression + SHA-256 check
        restored_data, metrics = crypto_engine.decrypt_file_data(
            ciphertext=ciphertext,
            password=password,
            salt_hex=backup['salt_hex'],
            nonce_hex=backup['nonce_hex'],
            tag_hex=backup['tag_hex'],
            expected_checksum=backup['checksum_sha256'],
            is_compressed=bool(backup['is_compressed'])
        )

        database.log_recovery(
            backup_id=backup_id,
            user_id=user_id,
            filename=backup['original_filename'],
            recovery_time_ms=metrics['recovery_time_ms'],
            status='SUCCESS'
        )

        database.log_security_event(
            user_id, username, 'BACKUP_RESTORED',
            f"Successfully restored backup #{backup_id} ('{backup['original_filename']}') in {metrics['recovery_time_ms']} ms",
            'SUCCESS', client_ip
        )

        # Return file for download
        return send_file(
            io.BytesIO(restored_data),
            as_attachment=True,
            download_name=backup['original_filename'],
            mimetype='application/octet-stream'
        )

    except crypto_engine.TamperDetectedError as e:
        database.log_recovery(backup_id, user_id, backup['original_filename'], 0, 'AUTH_FAILURE', str(e))
        database.log_security_event(user_id, username, 'RECOVERY_TAMPER_ALERT', f"Decryption/MAC failed on #{backup_id}: {str(e)}", 'FAILURE', client_ip)
        return jsonify({'success': False, 'message': str(e)}), 403

    except crypto_engine.IntegrityError as e:
        database.log_recovery(backup_id, user_id, backup['original_filename'], 0, 'INTEGRITY_FAILURE', str(e))
        database.log_security_event(user_id, username, 'INTEGRITY_VIOLATION', f"Checksum mismatch on #{backup_id}: {str(e)}", 'CRITICAL', client_ip)
        return jsonify({'success': False, 'message': str(e)}), 422

    except Exception as e:
        database.log_recovery(backup_id, user_id, backup['original_filename'], 0, 'ERROR', str(e))
        return jsonify({'success': False, 'message': f"Recovery error: {str(e)}"}), 500


@app.route('/api/download-encrypted/<int:backup_id>')
@login_required
def download_encrypted(backup_id):
    """Allows downloading the raw AES-256 ciphertext payload for cryptographic inspection."""
    user_id = session['user_id']
    backup = database.get_backup_by_id(backup_id, user_id=user_id)
    if not backup:
        return jsonify({'success': False, 'message': 'Access denied.'}), 404

    stored_path = os.path.join(config.ENCRYPTED_DIR, backup['encrypted_filename'])
    if not os.path.exists(stored_path):
        return jsonify({'success': False, 'message': 'File not found.'}), 404

    return send_file(
        stored_path,
        as_attachment=True,
        download_name=f"{backup['original_filename']}.aes256.enc",
        mimetype='application/octet-stream'
    )


@app.route('/api/delete/<int:backup_id>', methods=['POST'])
@login_required
def delete_backup(backup_id):
    user_id = session['user_id']
    username = session['username']
    backup = database.get_backup_by_id(backup_id, user_id=user_id)
    if not backup:
        return jsonify({'success': False, 'message': 'Backup not found or access denied.'}), 404

    stored_path = os.path.join(config.ENCRYPTED_DIR, backup['encrypted_filename'])
    if os.path.exists(stored_path):
        try:
            os.remove(stored_path)
        except OSError:
            pass

    database.delete_backup_record(backup_id, user_id)
    database.log_security_event(user_id, username, 'BACKUP_DELETED', f"Deleted backup #{backup_id} ('{backup['original_filename']}')", 'SUCCESS', request.remote_addr)
    return jsonify({'success': True, 'message': 'Backup deleted successfully.'})


# ---------------------------------------------------------------------
# Task 3: Performance Evaluation Page
# ---------------------------------------------------------------------

@app.route('/performance')
@login_required
def performance():
    user_id = session['user_id']
    summary, rec_summary = database.get_performance_stats(user_id)
    recent_backups = database.get_backups_for_user(user_id)
    recent_recoveries = database.get_recovery_logs_for_user(user_id)
    return render_template(
        'performance.html',
        summary=summary,
        rec_summary=rec_summary,
        recent_backups=recent_backups,
        recent_recoveries=recent_recoveries
    )


# ---------------------------------------------------------------------
# Audit Logs
# ---------------------------------------------------------------------

@app.route('/audit-logs')
@login_required
def audit_logs():
    user_id = session['user_id']
    logs = database.get_security_logs(limit=100, user_id=user_id)
    return render_template('audit_logs.html', logs=logs)


if __name__ == '__main__':
    # Local development server
    print("Starting AES-Based Secure Backup and Recovery System on http://127.0.0.1:5000 ...")
    app.run(host='127.0.0.1', port=5000, debug=True)
