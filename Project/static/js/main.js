document.addEventListener('DOMContentLoaded', () => {

    // --- Loading Overlay Helpers ---
    const loadingOverlay = document.getElementById('loadingOverlay');
    const loadingText = document.getElementById('loadingOverlayText');

    function showLoading(msg = 'Performing cryptographic operations...') {
        if (loadingOverlay) {
            loadingText.textContent = msg;
            loadingOverlay.style.display = 'flex';
        }
    }

    function hideLoading() {
        if (loadingOverlay) {
            loadingOverlay.style.display = 'none';
        }
    }

    // --- Dropzone & File Selection ---
    const dropzone = document.getElementById('dropzone');
    const fileInput = document.getElementById('fileInput');
    const selectedFileName = document.getElementById('selectedFileName');

    if (dropzone && fileInput) {
        dropzone.addEventListener('click', () => fileInput.click());

        dropzone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropzone.classList.add('dragover');
        });

        dropzone.addEventListener('dragleave', () => {
            dropzone.classList.remove('dragover');
        });

        dropzone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropzone.classList.remove('dragover');
            if (e.dataTransfer.files.length > 0) {
                fileInput.files = e.dataTransfer.files;
                updateFileDisplay();
            }
        });

        fileInput.addEventListener('change', updateFileDisplay);

        function updateFileDisplay() {
            if (fileInput.files.length > 0) {
                const file = fileInput.files[0];
                const sizeKb = (file.size / 1024).toFixed(1);
                selectedFileName.textContent = `${file.name} (${sizeKb} KB)`;
                selectedFileName.classList.remove('d-none');
            }
        }
    }

    // --- Backup Upload AJAX ---
    const backupForm = document.getElementById('backupUploadForm');
    const feedbackBox = document.getElementById('backupFeedback');

    if (backupForm) {
        backupForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            if (!fileInput.files || fileInput.files.length === 0) {
                alert('Please select a file to backup.');
                return;
            }

            const password = document.getElementById('backupPassword').value;
            if (!password) {
                alert('Please enter your password to derive the AES key.');
                return;
            }

            showLoading('Compressing, deriving AES-256 key via scrypt, and encrypting...');

            const formData = new FormData(backupForm);

            try {
                const response = await fetch('/api/backup', {
                    method: 'POST',
                    body: formData
                });

                const result = await response.json();
                hideLoading();

                if (result.success) {
                    const m = result.metrics;
                    feedbackBox.className = 'mt-3 alert alert-success alert-dismissible fade show';
                    feedbackBox.innerHTML = `
                        <h6 class="fw-bold mb-2"><i class="fa-solid fa-circle-check me-2"></i>${result.message}</h6>
                        <ul class="mb-0 small">
                            <li><strong>Original Size:</strong> ${(m.original_size / 1024).toFixed(1)} KB &rarr; <strong>Encrypted Size:</strong> ${(m.encrypted_size / 1024).toFixed(1)} KB</li>
                            <li><strong>Space Saved:</strong> ${m.compression_ratio}% (Efficiency: ${m.storage_efficiency}%)</li>
                            <li><strong>Execution Latency:</strong> ${m.backup_time_ms} ms (Throughput: ${m.throughput_mb_s} MB/s)</li>
                            <li><strong>SHA-256 Checksum:</strong> <code class="text-light text-break font-monospace">${m.sha256}</code> 
                                <button type="button" class="btn btn-sm btn-outline-info py-0 px-2 ms-1 btn-copy-hash" data-hash="${m.sha256}" title="Copy SHA-256">
                                    <i class="fa-regular fa-copy"></i>
                                </button>
                            </li>
                        </ul>
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    `;
                    feedbackBox.classList.remove('d-none');

                    // Bind copy button on newly created feedback
                    const newCopyBtn = feedbackBox.querySelector('.btn-copy-hash');
                    if (newCopyBtn) {
                        newCopyBtn.addEventListener('click', async () => {
                            await copyTextToClipboard(m.sha256);
                            newCopyBtn.innerHTML = '<i class="fa-solid fa-check text-success"></i> Copied!';
                        });
                    }

                    // Reset form
                    backupForm.reset();
                    selectedFileName.classList.add('d-none');

                    // Reload page after delay to display in table
                    setTimeout(() => window.location.reload(), 2500);
                } else {
                    feedbackBox.className = 'mt-3 alert alert-danger alert-dismissible fade show';
                    feedbackBox.innerHTML = `<i class="fa-solid fa-triangle-exclamation me-2"></i> ${result.message}`;
                    feedbackBox.classList.remove('d-none');
                }
            } catch (err) {
                hideLoading();
                alert('Error uploading backup: ' + err);
            }
        });
    }

    // --- Recovery Workflow ---
    let activeRecoveryBackupId = null;
    let activeRecoveryFilename = null;
    const recoveryModalElement = document.getElementById('recoveryModal');
    let recoveryModal = null;
    if (recoveryModalElement) {
        recoveryModal = new bootstrap.Modal(recoveryModalElement);
    }
    const recoveryFilenameEl = document.getElementById('recoveryFilename');
    const recoveryPasswordInput = document.getElementById('recoveryPasswordInput');
    const recoveryErrorAlert = document.getElementById('recoveryErrorAlert');
    const confirmRecoveryBtn = document.getElementById('confirmRecoveryBtn');

    document.querySelectorAll('.btn-recover').forEach(btn => {
        btn.addEventListener('click', () => {
            activeRecoveryBackupId = btn.getAttribute('data-id');
            activeRecoveryFilename = btn.getAttribute('data-filename');
            recoveryFilenameEl.textContent = activeRecoveryFilename;
            recoveryPasswordInput.value = '';
            recoveryErrorAlert.classList.add('d-none');
            recoveryModal.show();
        });
    });

    if (confirmRecoveryBtn) {
        confirmRecoveryBtn.addEventListener('click', async () => {
            const password = recoveryPasswordInput.value;
            if (!password) {
                recoveryErrorAlert.textContent = 'Please enter your password.';
                recoveryErrorAlert.classList.remove('d-none');
                return;
            }

            confirmRecoveryBtn.disabled = true;
            confirmRecoveryBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span> Decrypting...';
            recoveryErrorAlert.classList.add('d-none');

            const formData = new FormData();
            formData.append('password', password);

            try {
                const response = await fetch(`/api/recover/${activeRecoveryBackupId}`, {
                    method: 'POST',
                    body: formData
                });

                if (response.ok) {
                    // Successful decryption! Trigger file download directly from response blob
                    const blob = await response.blob();
                    const downloadUrl = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = downloadUrl;
                    a.download = activeRecoveryFilename;
                    document.body.appendChild(a);
                    a.click();
                    a.remove();
                    window.URL.revokeObjectURL(downloadUrl);

                    recoveryModal.hide();
                    alert(`Backup restored successfully! '${activeRecoveryFilename}' downloaded.`);
                } else {
                    const errResult = await response.json();
                    recoveryErrorAlert.innerHTML = `<i class="fa-solid fa-triangle-exclamation me-1"></i> ${errResult.message}`;
                    recoveryErrorAlert.classList.remove('d-none');
                }
            } catch (err) {
                recoveryErrorAlert.textContent = 'Recovery request failed: ' + err;
                recoveryErrorAlert.classList.remove('d-none');
            } finally {
                confirmRecoveryBtn.disabled = false;
                confirmRecoveryBtn.innerHTML = '<i class="fa-solid fa-unlock me-1"></i> Verify & Decrypt';
            }
        });
    }

    // --- Copy Helper ---
    async function copyTextToClipboard(text) {
        if (navigator.clipboard && window.isSecureContext) {
            return navigator.clipboard.writeText(text);
        } else {
            const textArea = document.createElement('textarea');
            textArea.value = text;
            textArea.style.position = 'fixed';
            textArea.style.left = '-999999px';
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            try {
                document.execCommand('copy');
            } finally {
                textArea.remove();
            }
            return Promise.resolve();
        }
    }

    // --- SHA-256 View & Copy Modal Logic ---
    const sha256ModalEl = document.getElementById('sha256Modal');
    let sha256Modal = null;
    if (sha256ModalEl) {
        sha256Modal = new bootstrap.Modal(sha256ModalEl);
    }
    const modalSha256Filename = document.getElementById('modalSha256Filename');
    const modalSha256Input = document.getElementById('modalSha256Input');
    const modalCopyAlert = document.getElementById('modalCopyAlert');
    const btnModalCopySha256 = document.getElementById('btnModalCopySha256');

    // Click on SHA-256 badge to view modal
    document.querySelectorAll('.btn-view-hash').forEach(btn => {
        btn.addEventListener('click', () => {
            const hash = btn.getAttribute('data-hash');
            const filename = btn.getAttribute('data-filename') || 'File Checksum';
            if (modalSha256Filename) modalSha256Filename.textContent = filename;
            if (modalSha256Input) modalSha256Input.value = hash;
            if (modalCopyAlert) modalCopyAlert.classList.add('d-none');
            if (sha256Modal) sha256Modal.show();
        });
    });

    // Modal Copy Button
    if (btnModalCopySha256 && modalSha256Input) {
        btnModalCopySha256.addEventListener('click', async () => {
            await copyTextToClipboard(modalSha256Input.value);
            if (modalCopyAlert) modalCopyAlert.classList.remove('d-none');
            btnModalCopySha256.innerHTML = '<i class="fa-solid fa-check me-1"></i> Copied!';
            setTimeout(() => {
                btnModalCopySha256.innerHTML = '<i class="fa-regular fa-copy me-1"></i> Copy SHA-256';
            }, 2000);
        });
    }

    // Inline Table Copy Button
    document.querySelectorAll('.btn-copy-hash').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            e.stopPropagation();
            const hash = btn.getAttribute('data-hash');
            if (hash) {
                await copyTextToClipboard(hash);
                const originalHtml = btn.innerHTML;
                btn.innerHTML = '<i class="fa-solid fa-check text-success"></i>';
                btn.classList.add('border-success');
                setTimeout(() => {
                    btn.innerHTML = originalHtml;
                    btn.classList.remove('border-success');
                }, 2000);
            }
        });
    });

    // --- Delete Backup ---
    document.querySelectorAll('.btn-delete').forEach(btn => {
        btn.addEventListener('click', async () => {
            const backupId = btn.getAttribute('data-id');
            const filename = btn.getAttribute('data-filename');

            if (!confirm(`Are you sure you want to delete backup #${backupId} ('${filename}')? This action cannot be undone.`)) {
                return;
            }

            try {
                const response = await fetch(`/api/delete/${backupId}`, { method: 'POST' });
                const res = await response.json();
                if (res.success) {
                    const row = document.getElementById(`backup-row-${backupId}`);
                    if (row) row.remove();
                } else {
                    alert('Error deleting backup: ' + res.message);
                }
            } catch (err) {
                alert('Delete error: ' + err);
            }
        });
    });

});

