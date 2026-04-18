/**
 * Zero-Knowledge Cryptography Client
 * Browser-based encryption using Web Crypto API
 * AES-256-GCM with PBKDF2 key derivation
 */

class CryptoClient {
  constructor() {
    this.ALGORITHM = 'AES-GCM';
    this.KEY_LENGTH = 256;
    this.IV_LENGTH = 12; // 96 bits for GCM
    this.SALT_LENGTH = 16; // 128 bits
    this.PBKDF2_ITERATIONS = 100000;
    this.TAG_LENGTH = 128; // GCM authentication tag
  }

  /**
   * Generate a random salt
   */
  generateSalt() {
    return crypto.getRandomValues(new Uint8Array(this.SALT_LENGTH));
  }

  /**
   * Generate a random IV
   */
  generateIV() {
    return crypto.getRandomValues(new Uint8Array(this.IV_LENGTH));
  }

  /**
   * Derive encryption key from password using PBKDF2
   */
  async deriveKey(password, salt) {
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);

    // Import password as key material
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      passwordBuffer,
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );

    // Derive AES key
    return await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: this.PBKDF2_ITERATIONS,
        hash: 'SHA-256'
      },
      keyMaterial,
      {
        name: this.ALGORITHM,
        length: this.KEY_LENGTH
      },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Encrypt data with password
   * Returns: [Salt: 16 bytes][IV: 12 bytes][Encrypted Data with Auth Tag]
   */
  async encrypt(data, password) {
    try {
      // Generate salt and IV
      const salt = this.generateSalt();
      const iv = this.generateIV();

      // Derive key from password
      const key = await this.deriveKey(password, salt);

      // Convert data to ArrayBuffer if needed
      let dataBuffer;
      if (data instanceof ArrayBuffer) {
        dataBuffer = data;
      } else if (data instanceof Uint8Array) {
        dataBuffer = data.buffer;
      } else if (typeof data === 'string') {
        const encoder = new TextEncoder();
        dataBuffer = encoder.encode(data);
      } else {
        throw new Error('Unsupported data type');
      }

      // Encrypt
      const encryptedData = await crypto.subtle.encrypt(
        {
          name: this.ALGORITHM,
          iv: iv,
          tagLength: this.TAG_LENGTH
        },
        key,
        dataBuffer
      );

      // Combine salt + iv + encrypted data
      const result = new Uint8Array(
        this.SALT_LENGTH + this.IV_LENGTH + encryptedData.byteLength
      );
      result.set(salt, 0);
      result.set(iv, this.SALT_LENGTH);
      result.set(new Uint8Array(encryptedData), this.SALT_LENGTH + this.IV_LENGTH);

      return result;
    } catch (error) {
      console.error('Encryption error:', error);
      throw new Error('Encryption failed: ' + error.message);
    }
  }

  /**
   * Decrypt data with password
   * Input format: [Salt: 16 bytes][IV: 12 bytes][Encrypted Data with Auth Tag]
   */
  async decrypt(encryptedData, password) {
    try {
      // Convert to Uint8Array if needed
      let dataArray;
      if (encryptedData instanceof ArrayBuffer) {
        dataArray = new Uint8Array(encryptedData);
      } else if (encryptedData instanceof Uint8Array) {
        dataArray = encryptedData;
      } else {
        throw new Error('Invalid encrypted data format');
      }

      // Validate minimum length
      const minLength = this.SALT_LENGTH + this.IV_LENGTH + 16; // 16 bytes for auth tag
      if (dataArray.length < minLength) {
        throw new Error('Encrypted data too short');
      }

      // Extract salt, iv, and encrypted content
      const salt = dataArray.slice(0, this.SALT_LENGTH);
      const iv = dataArray.slice(this.SALT_LENGTH, this.SALT_LENGTH + this.IV_LENGTH);
      const encryptedContent = dataArray.slice(this.SALT_LENGTH + this.IV_LENGTH);

      // Derive key from password
      const key = await this.deriveKey(password, salt);

      // Decrypt
      const decryptedData = await crypto.subtle.decrypt(
        {
          name: this.ALGORITHM,
          iv: iv,
          tagLength: this.TAG_LENGTH
        },
        key,
        encryptedContent
      );

      return new Uint8Array(decryptedData);
    } catch (error) {
      console.error('Decryption error:', error);
      if (error.name === 'OperationError') {
        throw new Error('Decryption failed: Wrong password or corrupted data');
      }
      throw new Error('Decryption failed: ' + error.message);
    }
  }

  /**
   * Encrypt a file
   */
  async encryptFile(file, password) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      
      reader.onload = async (e) => {
        try {
          const fileData = e.target.result;
          const encrypted = await this.encrypt(fileData, password);
          
          // Create a new Blob with encrypted data
          const encryptedBlob = new Blob([encrypted], { type: 'application/octet-stream' });
          
          resolve(encryptedBlob);
        } catch (error) {
          reject(error);
        }
      };
      
      reader.onerror = () => reject(new Error('Failed to read file'));
      reader.readAsArrayBuffer(file);
    });
  }

  /**
   * Decrypt a file
   */
  async decryptFile(encryptedBlob, password) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      
      reader.onload = async (e) => {
        try {
          const encryptedData = e.target.result;
          const decrypted = await this.decrypt(encryptedData, password);
          
          resolve(decrypted);
        } catch (error) {
          reject(error);
        }
      };
      
      reader.onerror = () => reject(new Error('Failed to read encrypted file'));
      reader.readAsArrayBuffer(encryptedBlob);
    });
  }

  /**
   * Hash data using SHA-256
   */
  async hash(data) {
    let buffer;
    if (typeof data === 'string') {
      const encoder = new TextEncoder();
      buffer = encoder.encode(data);
    } else if (data instanceof ArrayBuffer) {
      buffer = data;
    } else if (data instanceof Uint8Array) {
      buffer = data.buffer;
    } else {
      throw new Error('Unsupported data type for hashing');
    }

    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Convert ArrayBuffer to Base64
   */
  arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  /**
   * Convert Base64 to ArrayBuffer
   */
  base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }
}

// Create global instance
window.cryptoClient = new CryptoClient();
