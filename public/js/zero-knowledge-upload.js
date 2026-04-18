/**
 * Zero-Knowledge Upload Handler
 * Encrypts files in the browser before uploading to server
 */

(function() {
  'use strict';

  // Wait for DOM to be ready
  document.addEventListener('DOMContentLoaded', function() {
    initializeZeroKnowledgeUpload();
  });

  function initializeZeroKnowledgeUpload() {
    const uploadForm = document.getElementById('upload-form');
    if (!uploadForm) {
      console.warn('Upload form not found');
      return;
    }

    // Add zero-knowledge mode checkbox if it doesn't exist
    addZeroKnowledgeModeCheckbox();

    // Intercept form submission
    uploadForm.addEventListener('submit', handleZeroKnowledgeUpload);
  }

  function addZeroKnowledgeModeCheckbox() {
    const uploadForm = document.getElementById('upload-form');
    const fileInput = uploadForm.querySelector('input[type="file"]');
    
    if (!fileInput) return;

    // Check if checkbox already exists
    if (document.getElementById('zeroKnowledgeMode')) return;

    // Create checkbox container
    const checkboxContainer = document.createElement('div');
    checkboxContainer.className = 'form-group';
    checkboxContainer.style.marginTop = '10px';
    
    const label = document.createElement('label');
    label.style.display = 'flex';
    label.style.alignItems = 'center';
    label.style.cursor = 'pointer';
    
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.id = 'zeroKnowledgeMode';
    checkbox.name = 'zeroKnowledgeMode';
    checkbox.style.marginRight = '8px';
    
    const labelText = document.createElement('span');
    labelText.textContent = 'Zero-Knowledge Mode (Encrypt in browser before upload)';
    labelText.style.fontWeight = 'bold';
    labelText.style.color = '#2ecc71';
    
    label.appendChild(checkbox);
    label.appendChild(labelText);
    checkboxContainer.appendChild(label);
    
    // Add help text
    const helpText = document.createElement('small');
    helpText.style.display = 'block';
    helpText.style.marginTop = '5px';
    helpText.style.color = '#7f8c8d';
    helpText.textContent = 'Server will never see your unencrypted file. You must remember your password!';
    checkboxContainer.appendChild(helpText);
    
    // Insert after file input
    fileInput.parentNode.insertBefore(checkboxContainer, fileInput.nextSibling);
  }

  async function handleZeroKnowledgeUpload(event) {
    const zeroKnowledgeCheckbox = document.getElementById('zeroKnowledgeMode');
    
    // If zero-knowledge mode is not enabled, let normal upload proceed
    if (!zeroKnowledgeCheckbox || !zeroKnowledgeCheckbox.checked) {
      return; // Normal upload
    }

    // Prevent default form submission
    event.preventDefault();
    event.stopPropagation();

    try {
      await performZeroKnowledgeUpload(event.target);
    } catch (error) {
      console.error('Zero-knowledge upload error:', error);
      alert('Upload failed: ' + error.message);
    }
  }

  async function performZeroKnowledgeUpload(form) {
    const fileInput = form.querySelector('input[type="file"]');
    const file = fileInput.files[0];
    
    if (!file) {
      alert('Please select a file');
      return;
    }

    // Get encryption password from the form
    const password = document.getElementById('zk-password').value;
    const confirmPassword = document.getElementById('zk-password-confirm').value;
    
    if (!password) {
      alert('Please enter an encryption password');
      return;
    }

    if (password.length < 8) {
      alert('Password must be at least 8 characters');
      return;
    }

    if (password !== confirmPassword) {
      alert('Passwords do not match');
      return;
    }

    // Show progress
    const progressDiv = document.createElement('div');
    progressDiv.style.cssText = 'position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); background: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); z-index: 10000;';
    progressDiv.innerHTML = '<p style="margin: 0; font-weight: bold;">Encrypting file...</p><p style="margin: 10px 0 0 0; color: #7f8c8d;">Please wait, do not close this page.</p>';
    document.body.appendChild(progressDiv);

    try {
      // Encrypt file in browser
      console.log('Encrypting file:', file.name);
      const encryptedBlob = await window.cryptoClient.encryptFile(file, password);
      console.log('File encrypted successfully');

      // Prepare encrypted metadata
      const metadata = {
        originalName: file.name,
        originalSize: file.size,
        originalType: file.type,
        encryptedAt: new Date().toISOString()
      };
      const metadataJson = JSON.stringify(metadata);
      const encryptedMetadata = await window.cryptoClient.encrypt(metadataJson, password);
      const encryptedMetadataBase64 = window.cryptoClient.arrayBufferToBase64(encryptedMetadata);

      // Update progress
      progressDiv.innerHTML = '<p style="margin: 0; font-weight: bold;">Uploading encrypted file...</p>';

      // Create FormData with encrypted file
      const formData = new FormData();
      
      // Add encrypted file with .enc extension
      const encryptedFileName = file.name + '.enc';
      formData.append('file', encryptedBlob, encryptedFileName);
      
      // Add zero-knowledge flags
      formData.append('clientSideEncrypted', 'true');
      formData.append('encryptedMetadata', encryptedMetadataBase64);
      
      // Add other form fields
      const encryptCheckbox = form.querySelector('input[name="encrypt"]');
      if (encryptCheckbox) {
        formData.append('encrypt', encryptCheckbox.checked);
      }
      
      const useUserKeyCheckbox = form.querySelector('input[name="useUserKey"]');
      if (useUserKeyCheckbox) {
        formData.append('useUserKey', useUserKeyCheckbox.checked);
      }

      // Upload to server
      const response = await fetch('/api/files/upload', {
        method: 'POST',
        body: formData,
        credentials: 'include'
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Upload failed');
      }

      const result = await response.json();
      console.log('Upload successful:', result);

      // Remove progress
      document.body.removeChild(progressDiv);

      // Show success message
      alert('File encrypted and uploaded successfully!\n\nIMPORTANT: Remember your password - it cannot be recovered!');

      // Reload page to show new file
      window.location.reload();

    } catch (error) {
      // Remove progress
      if (progressDiv.parentNode) {
        document.body.removeChild(progressDiv);
      }
      throw error;
    }
  }

})();
