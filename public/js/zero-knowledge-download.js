/**
 * Zero-Knowledge Download Handler
 * Decrypts files in the browser after downloading from server
 */

(function() {
  'use strict';

  // Wait for DOM to be ready
  document.addEventListener('DOMContentLoaded', function() {
    initializeZeroKnowledgeDownload();
  });

  function initializeZeroKnowledgeDownload() {
    // Intercept all download links
    document.addEventListener('click', handleDownloadClick);
  }

  function handleDownloadClick(event) {
    const target = event.target;
    
    // Check if this is a download link for a zero-knowledge encrypted file
    const downloadLink = target.closest('a[href*="/api/files/"][href*="/download"]');
    if (!downloadLink) return;

    // Check if file is client-side encrypted (look for indicator in the UI)
    const fileRow = downloadLink.closest('tr') || downloadLink.closest('.file-item');
    if (!fileRow) return;

    // Look for zero-knowledge indicator
    const isZeroKnowledge = fileRow.textContent.includes('🔐') || 
                           fileRow.textContent.includes('Zero-Knowledge') ||
                           fileRow.querySelector('.zero-knowledge-badge');

    if (!isZeroKnowledge) return;

    // Prevent default download
    event.preventDefault();
    event.stopPropagation();

    // Perform zero-knowledge download
    performZeroKnowledgeDownload(downloadLink.href, fileRow);
  }

  async function performZeroKnowledgeDownload(downloadUrl, fileRow) {
    try {
      // Get file name from the row
      const fileNameElement = fileRow.querySelector('.file-name') || 
                             fileRow.querySelector('td:first-child') ||
                             fileRow;
      const fileName = fileNameElement.textContent.trim().replace('.enc', '');

      // Ask for decryption password
      const password = prompt('Enter decryption password for: ' + fileName + '\n\nThis is the password you used when uploading the file.');
      
      if (!password) {
        return; // User cancelled
      }

      // Show progress
      const progressDiv = document.createElement('div');
      progressDiv.style.cssText = 'position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); background: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); z-index: 10000;';
      progressDiv.innerHTML = '<p style="margin: 0; font-weight: bold;">Downloading encrypted file...</p><p style="margin: 10px 0 0 0; color: #7f8c8d;">Please wait...</p>';
      document.body.appendChild(progressDiv);

      // Download encrypted file
      const response = await fetch(downloadUrl, {
        credentials: 'include'
      });

      if (!response.ok) {
        throw new Error('Download failed: ' + response.statusText);
      }

      const encryptedBlob = await response.blob();
      console.log('Downloaded encrypted file, size:', encryptedBlob.size);

      // Update progress
      progressDiv.innerHTML = '<p style="margin: 0; font-weight: bold;">Decrypting file...</p><p style="margin: 10px 0 0 0; color: #7f8c8d;">Please wait...</p>';

      // Decrypt file in browser
      const decryptedData = await window.cryptoClient.decryptFile(encryptedBlob, password);
      console.log('File decrypted successfully');

      // Try to get original metadata if available
      let originalFileName = fileName;
      let originalMimeType = 'application/octet-stream';

      // Attempt to decrypt metadata from file info
      try {
        const fileId = downloadUrl.match(/\/files\/([^\/]+)\//)?.[1];
        if (fileId) {
          const infoResponse = await fetch(`/api/files/${fileId}`, {
            credentials: 'include'
          });
          if (infoResponse.ok) {
            const fileInfo = await infoResponse.json();
            if (fileInfo.encryptedMetadata) {
              const metadataBuffer = window.cryptoClient.base64ToArrayBuffer(fileInfo.encryptedMetadata);
              const decryptedMetadata = await window.cryptoClient.decrypt(metadataBuffer, password);
              const metadataText = new TextDecoder().decode(decryptedMetadata);
              const metadata = JSON.parse(metadataText);
              originalFileName = metadata.originalName || fileName;
              originalMimeType = metadata.originalType || originalMimeType;
            }
          }
        }
      } catch (metadataError) {
        console.warn('Could not decrypt metadata:', metadataError);
        // Continue with default filename
      }

      // Create blob with decrypted data
      const decryptedBlob = new Blob([decryptedData], { type: originalMimeType });

      // Trigger download
      const url = URL.createObjectURL(decryptedBlob);
      const a = document.createElement('a');
      a.href = url;
      a.download = originalFileName;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      // Remove progress
      document.body.removeChild(progressDiv);

      // Show success message
      alert('File decrypted successfully!');

    } catch (error) {
      console.error('Zero-knowledge download error:', error);
      
      // Remove progress if it exists
      const progressDiv = document.querySelector('div[style*="position: fixed"]');
      if (progressDiv) {
        document.body.removeChild(progressDiv);
      }

      if (error.message.includes('Wrong password')) {
        alert('Decryption failed: Wrong password\n\nPlease try again with the correct password.');
      } else {
        alert('Download/decryption failed: ' + error.message);
      }
    }
  }

  // Add visual indicators for zero-knowledge files
  function addZeroKnowledgeIndicators() {
    // This function can be called to add badges to zero-knowledge encrypted files
    // Look for files with encryptionVersion: 99 or userKeyEncrypted flag
    const fileRows = document.querySelectorAll('tr[data-file-id]');
    
    fileRows.forEach(row => {
      const encryptionVersion = row.dataset.encryptionVersion;
      if (encryptionVersion === '99') {
        // Add zero-knowledge badge
        const badge = document.createElement('span');
        badge.className = 'zero-knowledge-badge';
        badge.textContent = '🔐 Zero-Knowledge';
        badge.style.cssText = 'background: #2ecc71; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; margin-left: 8px;';
        
        const fileNameCell = row.querySelector('td:first-child');
        if (fileNameCell && !fileNameCell.querySelector('.zero-knowledge-badge')) {
          fileNameCell.appendChild(badge);
        }
      }
    });
  }

  // Run indicator check after page loads
  setTimeout(addZeroKnowledgeIndicators, 500);

})();
