//! AES-GCM and AES-CTR Ciphers for SSH
//!
//! This module implements AES-GCM (Galois/Counter Mode) authenticated encryption
//! and AES-CTR (Counter Mode) for SSH as defined in RFC 4253 and RFC 4344.
//!
//! # AES-GCM Overview
//!
//! AES-GCM is an authenticated encryption mode that combines:
//! - AES in Counter mode (CTR) for encryption
//! - Galois Counter Mode (GCM) for authentication
//!
//! It provides:
//! - **Confidentiality**: Encrypts data using AES-256
//! - **Integrity**: Authenticates data using a 128-bit authentication tag
//! - **Non-repudiation**: Prevents tampering detection
//!
//! # AES-CTR Overview
//!
//! AES-CTR is a stream cipher mode that provides:
//! - **Confidentiality**: Encrypts data using AES-256 in counter mode
//! - Used with HMAC for integrity (RFC 4344)
//!
//! # SSH Usage
//!
//! In SSH (RFC 4253, RFC 4344), AES-GCM and AES-CTR are used to protect
//! the confidentiality and integrity of data transferred over the secure channel.
//! The ciphers use:
//! - 256-bit keys (32 bytes)
//! - 96-bit nonces (12 bytes for GCM, 8 bytes for CTR counter)
//! - 128-bit authentication tags for GCM (16 bytes)
//!
//! # Security Considerations
//!
//! - Always use unique nonces for the same key
//! - Never reuse a (key, nonce) pair
//! - The authentication tag is appended to ciphertext (GCM only)
//! - Verify authentication before decrypting sensitive data
//! - For CTR mode, always use HMAC for integrity protection

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use thiserror::Error;

/// Error type for cipher operations
#[derive(Debug, Error, PartialEq)]
pub enum CipherError {
    /// Invalid key size (expected 32 bytes for AES-256 or 16 bytes for AES-128)
    #[error("Invalid key size: expected {expected} bytes, got {actual}")]
    InvalidKeySize { expected: usize, actual: usize },
    
    /// Invalid nonce size (expected 12 bytes for AES-GCM)
    #[error("Invalid nonce size: expected 12 bytes for GCM")]
    InvalidNonceSizeGcm,
    
    /// Invalid nonce size (expected 8 bytes for AES-CTR)
    #[error("Invalid nonce size: expected 8 bytes for CTR")]
    InvalidNonceSizeCtr,
    
    /// Invalid IV size (expected 16 bytes for CBC)
    #[error("Invalid IV size: expected 16 bytes for CBC")]
    InvalidIvSizeCbc,
    
    /// Invalid padding (PKCS#7 validation failed)
    #[error("Invalid padding: PKCS#7 validation failed")]
    InvalidPadding,
    
    /// Authentication failed (tampered or corrupted data)
    #[error("Authentication failed")]
    AuthenticationFailed,
    
    /// Encryption/decryption error
    #[error("Encryption/decryption error: {0}")]
    CryptoError(String),
}

/// Encrypt data using AES-256-GCM
///
/// # Arguments
///
/// * `key` - 32-byte (256-bit) encryption key
/// * `nonce` - 12-byte (96-bit) nonce (must be unique per encryption)
/// * `plaintext` - Data to encrypt
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Ciphertext with authentication tag appended
/// * `Err(CipherError)` - Error if key/nonce size is invalid or encryption fails
///
/// # Example
///
/// ```
/// use ssh_client::crypto::cipher::{aes_gcm_encrypt, aes_gcm_decrypt};
///
/// let key = vec![0x00; 32];
/// let nonce = vec![0x00; 12];
/// let plaintext = b"Hello, SSH!";
///
/// let ciphertext = aes_gcm_encrypt(&key, &nonce, plaintext).unwrap();
/// let decrypted = aes_gcm_decrypt(&key, &nonce, &ciphertext).unwrap();
///
/// assert_eq!(decrypted, plaintext);
/// ```
pub fn aes_gcm_encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
    // Validate key size
    if key.len() != 32 {
        return Err(CipherError::InvalidKeySize { expected: 32, actual: key.len() });
    }
    
    // Validate nonce size
    if nonce.len() != 12 {
        return Err(CipherError::InvalidNonceSizeGcm);
    }
    
    // Create AES-256-GCM key
    let key = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|e| CipherError::CryptoError(e.to_string()))?;
    let encrypting_key = LessSafeKey::new(key);
    
    // Create nonce
    let nonce = Nonce::try_assume_unique_for_key(nonce)
        .map_err(|e| CipherError::CryptoError(e.to_string()))?;
    
    // Encrypt - we need to copy plaintext to a mutable buffer
    let mut buffer = plaintext.to_vec();
    let tag = encrypting_key
        .seal_in_place_separate_tag(nonce, Aad::empty(), &mut buffer)
        .map_err(|e| CipherError::CryptoError(e.to_string()))?;
    
    // Append tag to ciphertext
    buffer.extend_from_slice(tag.as_ref());
    Ok(buffer)
}

/// Decrypt data using AES-256-GCM
///
/// # Arguments
///
/// * `key` - 32-byte (256-bit) encryption key
/// * `nonce` - 12-byte (96-bit) nonce (must match encryption nonce)
/// * `ciphertext` - Ciphertext with authentication tag
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Decrypted plaintext
/// * `Err(CipherError)` - Error if key/nonce size is invalid or authentication fails
///
/// # Example
///
/// ```
/// use ssh_client::crypto::cipher::{aes_gcm_encrypt, aes_gcm_decrypt};
///
/// let key = vec![0x00; 32];
/// let nonce = vec![0x00; 12];
/// let plaintext = b"Hello, SSH!";
///
/// let ciphertext = aes_gcm_encrypt(&key, &nonce, plaintext).unwrap();
/// let decrypted = aes_gcm_decrypt(&key, &nonce, &ciphertext).unwrap();
///
/// assert_eq!(decrypted, plaintext);
/// ```
pub fn aes_gcm_decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CipherError> {
    // Validate key size
    if key.len() != 32 {
        return Err(CipherError::InvalidKeySize { expected: 32, actual: key.len() });
    }
    
    // Validate nonce size
    if nonce.len() != 12 {
        return Err(CipherError::InvalidNonceSizeGcm);
    }
    
    // Split ciphertext and tag (last 16 bytes is the tag)
    if ciphertext.len() < 16 {
        return Err(CipherError::AuthenticationFailed);
    }
    
    let (ciphertext_only, tag_bytes) = ciphertext.split_at(ciphertext.len() - 16);
    
    // Create AES-256-GCM key
    let key = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|e| CipherError::CryptoError(e.to_string()))?;
    let decrypting_key = LessSafeKey::new(key);
    
    // Create nonce
    let nonce = Nonce::try_assume_unique_for_key(nonce)
        .map_err(|e| CipherError::CryptoError(e.to_string()))?;
    
    // Decrypt using open_in_place_separate_tag
    let mut buffer = ciphertext_only.to_vec();
    
    // Convert tag_bytes to Tag
    use ring::aead::Tag;
    let tag = Tag::try_from(tag_bytes).map_err(|_| CipherError::AuthenticationFailed)?;
    
    match decrypting_key.open_in_place_separate_tag(
        nonce,
        Aad::empty(),
        tag,
        &mut buffer,
        0..,
    ) {
        Ok(_) => Ok(buffer),
        Err(_) => Err(CipherError::AuthenticationFailed),
    }
}

/// Encrypt data using AES-256-CTR mode
///
/// AES-CTR mode is defined in RFC 4344 for SSH. It uses AES in counter mode
/// to create a stream cipher. For integrity protection, HMAC should be used
/// separately (typically HMAC-SHA2-256 or HMAC-SHA2-512).
///
/// # Arguments
///
/// * `key` - 32-byte (256-bit) encryption key
/// * `nonce` - 8-byte (64-bit) counter nonce
/// * `plaintext` - Data to encrypt
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Encrypted data
/// * `Err(CipherError)` - Error if key/nonce size is invalid or encryption fails
///
/// # Security Notes
///
/// - CTR mode provides confidentiality but NOT integrity
/// - Always use HMAC separately for integrity protection
/// - The counter must never repeat for the same key
pub fn aes_ctr_encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
    // Validate key size
    if key.len() != 32 {
        return Err(CipherError::InvalidKeySize { expected: 32, actual: key.len() });
    }
    
    // Validate nonce size (8 bytes for CTR mode)
    if nonce.len() != 8 {
        return Err(CipherError::InvalidNonceSizeCtr);
    }
    
    // AES-CTR encryption: XOR plaintext with AES(key, counter)
    let mut ciphertext = plaintext.to_vec();
    
    // Process data in 16-byte blocks (AES block size)
    for (i, chunk) in ciphertext.chunks_mut(16).enumerate() {
        // Create counter block: nonce (8 bytes) + counter (8 bytes, big-endian)
        let mut counter_block = [0u8; 16];
        counter_block[..8].copy_from_slice(nonce);
        counter_block[8..].copy_from_slice(&(i as u64).to_be_bytes());
        
        // Encrypt counter block with AES-256 to get keystream
        let keystream = aes_ctr_encrypt_block(key, &counter_block);
        
        // XOR chunk with keystream
        for (j, byte) in chunk.iter_mut().enumerate() {
            *byte ^= keystream[j];
        }
    }
    
    Ok(ciphertext)
}

/// Decrypt data using AES-256-CTR mode
///
/// CTR mode decryption is identical to encryption (XOR operation).
///
/// # Arguments
///
/// * `key` - 32-byte (256-bit) encryption key
/// * `nonce` - 8-byte (64-bit) counter nonce (must match encryption nonce)
/// * `ciphertext` - Data to decrypt
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Decrypted plaintext
/// * `Err(CipherError)` - Error if key/nonce size is invalid or decryption fails
pub fn aes_ctr_decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CipherError> {
    // CTR mode decryption is identical to encryption
    aes_ctr_encrypt(key, nonce, ciphertext)
}

/// Encrypt a single 16-byte block with AES-256 for CTR mode
///
/// In CTR mode, we encrypt the counter block (not the data itself) and XOR
/// the result with the data. This function encrypts just the counter block.
fn aes_ctr_encrypt_block(key: &[u8], counter_block: &[u8]) -> [u8; 16] {
    use aes::cipher::{BlockEncrypt, KeyInit};
    use aes::Aes256;
    
    // Create AES-256 cipher from key
    let cipher = Aes256::new_from_slice(key).expect("Invalid key length");
    
    // Convert counter block to GenericArray
    let mut block = generic_array::GenericArray::<u8, _>::clone_from_slice(counter_block);
    
    // Encrypt the counter block
    cipher.encrypt_block(&mut block);
    
    // Convert back to array
    let mut result = [0u8; 16];
    result.copy_from_slice(&block);
    
    result
}

/// Apply PKCS#7 padding to data
///
/// PKCS#7 padding adds N bytes of value N to make the data fit a block size.
/// For AES, the block size is always 16 bytes.
fn apply_pkcs7_padding(data: &mut Vec<u8>, block_size: usize) {
    let padding_len = (block_size - (data.len() % block_size)) % block_size;
    if padding_len == 0 {
        // Data already fits, add a full block of padding
        let padding = vec![block_size as u8; block_size];
        data.extend_from_slice(&padding);
    } else {
        let padding = vec![padding_len as u8; padding_len];
        data.extend_from_slice(&padding);
    }
}

/// Remove PKCS#7 padding from data
///
/// Returns Ok(()) if padding is valid, Err(InvalidPadding) otherwise.
fn remove_pkcs7_padding(data: &mut Vec<u8>) -> Result<(), CipherError> {
    if data.is_empty() {
        return Err(CipherError::InvalidPadding);
    }
    
    let padding_len = data[data.len() - 1] as usize;
    
    if padding_len == 0 || padding_len > 16 {
        return Err(CipherError::InvalidPadding);
    }
    
    if data.len() < padding_len {
        return Err(CipherError::InvalidPadding);
    }
    
    // Verify all padding bytes have the correct value
    for &byte in data[data.len() - padding_len..].iter() {
        if byte != padding_len as u8 {
            return Err(CipherError::InvalidPadding);
        }
    }
    
    // Remove padding
    data.truncate(data.len() - padding_len);
    Ok(())
}

/// Encrypt data using AES-128-CBC mode
///
/// AES-CBC mode is defined in RFC 4470 for SSH. It uses AES in cipher block
/// chaining mode with PKCS#7 padding. For integrity protection, HMAC should be
/// used separately.
///
/// # Arguments
///
/// * `key` - 16-byte (128-bit) encryption key
/// * `iv` - 16-byte (128-bit) initialization vector
/// * `plaintext` - Data to encrypt
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Encrypted data with PKCS#7 padding
/// * `Err(CipherError)` - Error if key/iv size is invalid or encryption fails
///
/// # Security Notes
///
/// - CBC mode provides confidentiality but NOT integrity
/// - Always use HMAC separately for integrity protection
/// - CBC mode is deprecated (RFC 4470) but included for legacy compatibility
pub fn aes_128_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
    // Validate key size
    if key.len() != 16 {
        return Err(CipherError::InvalidKeySize { expected: 16, actual: key.len() });
    }
    
    // Validate IV size
    if iv.len() != 16 {
        return Err(CipherError::InvalidIvSizeCbc);
    }
    
    // Apply PKCS#7 padding
    let mut padded = plaintext.to_vec();
    apply_pkcs7_padding(&mut padded, 16);
    
    // Encrypt
    aes_cbc_encrypt_impl_128(key, iv, &padded)
}

/// Decrypt data using AES-128-CBC mode
///
/// CBC decryption decrypts each block and XORs it with the previous ciphertext
/// block (or IV for the first block).
///
/// # Arguments
///
/// * `key` - 16-byte (128-bit) encryption key
/// * `iv` - 16-byte (128-bit) initialization vector (must match encryption IV)
/// * `ciphertext` - Data to decrypt
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Decrypted plaintext (without padding)
/// * `Err(CipherError)` - Error if key/iv size is invalid, decryption fails, or padding is invalid
pub fn aes_128_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CipherError> {
    // Validate key size
    if key.len() != 16 {
        return Err(CipherError::InvalidKeySize { expected: 16, actual: key.len() });
    }
    
    // Validate IV size
    if iv.len() != 16 {
        return Err(CipherError::InvalidIvSizeCbc);
    }
    
    // Check ciphertext length (must be multiple of block size)
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return Err(CipherError::InvalidPadding);
    }
    
    // Decrypt using AES-128
    use aes::cipher::{BlockDecrypt, KeyInit};
    let cipher = aes::Aes128::new_from_slice(key).map_err(|e| {
        CipherError::CryptoError(format!("Invalid key: {}", e))
    })?;
    
    let mut blocks: Vec<u8> = ciphertext.to_vec();
    let mut prev_block = iv.to_vec();
    
    // Process data in 16-byte blocks
    for chunk in blocks.chunks_mut(16) {
        // Save the ciphertext block before modifying it (needed for next iteration's prev_block)
        let ciphertext_block: [u8; 16] = chunk.try_into().unwrap();
        
        // Decrypt the block first
        let mut block = generic_array::GenericArray::<u8, _>::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        
        // Now XOR the decrypted block with previous ciphertext block (or IV for first block)
        for (i, byte) in chunk.iter_mut().enumerate() {
            *byte = block[i] ^ prev_block[i];
        }
        
        // Update previous block to the ciphertext block (for next iteration)
        prev_block.copy_from_slice(&ciphertext_block);
    }
    
    // Remove PKCS#7 padding
    remove_pkcs7_padding(&mut blocks)?;
    
    Ok(blocks)
}

/// Decrypt data using AES-128-CBC mode WITHOUT removing padding
///
/// This function performs raw CBC decryption without PKCS#7 padding removal.
/// It is used for SSH transport layer where individual blocks need to be
/// decrypted without padding (e.g., decrypting the first block to get packet length).
///
/// # Arguments
///
/// * `key` - 16-byte (128-bit) encryption key
/// * `iv` - 16-byte (128-bit) initialization vector (must match encryption IV)
/// * `ciphertext` - Data to decrypt (must be multiple of 16 bytes)
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Decrypted data (with padding intact)
/// * `Err(CipherError)` - Error if key/iv size is invalid or decryption fails
pub fn aes_128_cbc_decrypt_raw(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CipherError> {
    // Validate key size
    if key.len() != 16 {
        return Err(CipherError::InvalidKeySize { expected: 16, actual: key.len() });
    }
    
    // Validate IV size
    if iv.len() != 16 {
        return Err(CipherError::InvalidIvSizeCbc);
    }
    
    // Check ciphertext length (must be multiple of block size)
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return Err(CipherError::InvalidPadding);
    }
    
    // Decrypt using AES-128
    use aes::cipher::{BlockDecrypt, KeyInit};
    let cipher = aes::Aes128::new_from_slice(key).map_err(|e| {
        CipherError::CryptoError(format!("Invalid key: {}", e))
    })?;
    
    let mut blocks: Vec<u8> = ciphertext.to_vec();
    let mut prev_block = iv.to_vec();
    
    // Process data in 16-byte blocks
    for chunk in blocks.chunks_mut(16) {
        // Save the ciphertext block before modifying it (needed for next iteration's prev_block)
        let ciphertext_block: [u8; 16] = chunk.try_into().unwrap();
        
        // Decrypt the block first
        let mut block = generic_array::GenericArray::<u8, _>::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        
        // Now XOR the decrypted block with previous ciphertext block (or IV for first block)
        for (i, byte) in chunk.iter_mut().enumerate() {
            *byte = block[i] ^ prev_block[i];
        }
        
        // Update previous block to the ciphertext block (for next iteration)
        prev_block.copy_from_slice(&ciphertext_block);
    }
    
    // Do NOT remove padding - caller handles this
    Ok(blocks)
}

/// Encrypt data using AES-256-CBC mode
///
/// # Arguments
///
/// * `key` - 32-byte (256-bit) encryption key
/// * `iv` - 16-byte (128-bit) initialization vector
/// * `plaintext` - Data to encrypt
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Encrypted data with PKCS#7 padding
/// * `Err(CipherError)` - Error if key/iv size is invalid or encryption fails
pub fn aes_256_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
    // Validate key size
    if key.len() != 32 {
        return Err(CipherError::InvalidKeySize { expected: 32, actual: key.len() });
    }
    
    // Validate IV size
    if iv.len() != 16 {
        return Err(CipherError::InvalidIvSizeCbc);
    }
    
    // Apply PKCS#7 padding
    let mut padded = plaintext.to_vec();
    apply_pkcs7_padding(&mut padded, 16);
    
    // Encrypt
    aes_cbc_encrypt_impl_256(key, iv, &padded)
}

/// Decrypt data using AES-256-CBC mode
///
/// CBC decryption decrypts each block and XORs it with the previous ciphertext
/// block (or IV for the first block).
///
/// # Arguments
///
/// * `key` - 32-byte (256-bit) encryption key
/// * `iv` - 16-byte (128-bit) initialization vector (must match encryption IV)
/// * `ciphertext` - Data to decrypt
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Decrypted plaintext (without padding)
/// * `Err(CipherError)` - Error if key/iv size is invalid, decryption fails, or padding is invalid
pub fn aes_256_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CipherError> {
    // Validate key size
    if key.len() != 32 {
        return Err(CipherError::InvalidKeySize { expected: 32, actual: key.len() });
    }
    
    // Validate IV size
    if iv.len() != 16 {
        return Err(CipherError::InvalidIvSizeCbc);
    }
    
    // Check ciphertext length (must be multiple of block size)
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return Err(CipherError::InvalidPadding);
    }
    
    // Decrypt using AES-256
    use aes::cipher::{BlockDecrypt, KeyInit};
    let cipher = aes::Aes256::new_from_slice(key).map_err(|e| {
        CipherError::CryptoError(format!("Invalid key: {}", e))
    })?;
    
    let mut blocks: Vec<u8> = ciphertext.to_vec();
    let mut prev_block = iv.to_vec();
    
    // Process data in 16-byte blocks
    for chunk in blocks.chunks_mut(16) {
        // Save the ciphertext block before modifying it (needed for next iteration's prev_block)
        let ciphertext_block: [u8; 16] = chunk.try_into().unwrap();
        
        // Decrypt the block first
        let mut block = generic_array::GenericArray::<u8, _>::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        
        // Now XOR the decrypted block with previous ciphertext block (or IV for first block)
        for (i, byte) in chunk.iter_mut().enumerate() {
            *byte = block[i] ^ prev_block[i];
        }
        
        // Update previous block to the ciphertext block (for next iteration)
        prev_block.copy_from_slice(&ciphertext_block);
    }
    
    // Remove PKCS#7 padding
    remove_pkcs7_padding(&mut blocks)?;
    
    Ok(blocks)
}

/// Common AES-CBC encryption implementation for 256-bit keys
fn aes_cbc_encrypt_impl_256(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, CipherError> {
    use aes::cipher::{BlockEncrypt, KeyInit};
    
    let cipher = aes::Aes256::new_from_slice(key).map_err(|e| {
        CipherError::CryptoError(format!("Invalid key: {}", e))
    })?;
    
    let mut blocks: Vec<u8> = data.to_vec();
    let mut prev_block = iv.to_vec();
    
    // Process data in 16-byte blocks
    for chunk in blocks.chunks_mut(16) {
        // XOR with previous ciphertext block (or IV for first block)
        for (i, byte) in chunk.iter_mut().enumerate() {
            *byte ^= prev_block[i];
        }
        
        // Encrypt the block
        let mut block = generic_array::GenericArray::<u8, _>::clone_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        chunk.copy_from_slice(&block);
        
        // Update previous block
        prev_block.copy_from_slice(chunk);
    }
    
    Ok(blocks)
}

/// Common AES-CBC encryption implementation for 128-bit keys
fn aes_cbc_encrypt_impl_128(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, CipherError> {
    use aes::cipher::{BlockEncrypt, KeyInit};
    
    let cipher = aes::Aes128::new_from_slice(key).map_err(|e| {
        CipherError::CryptoError(format!("Invalid key: {}", e))
    })?;
    
    let mut blocks: Vec<u8> = data.to_vec();
    let mut prev_block = iv.to_vec();
    
    // Process data in 16-byte blocks
    for chunk in blocks.chunks_mut(16) {
        // XOR with previous ciphertext block (or IV for first block)
        for (i, byte) in chunk.iter_mut().enumerate() {
            *byte ^= prev_block[i];
        }
        
        // Encrypt the block
        let mut block = generic_array::GenericArray::<u8, _>::clone_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        chunk.copy_from_slice(&block);
        
        // Update previous block
        prev_block.copy_from_slice(chunk);
    }
    
    Ok(blocks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_gcm_encrypt_decrypt() {
        let key = vec![0x00; 32];
        let nonce = vec![0x00; 12];
        let plaintext = b"Hello, World!";
        
        let ciphertext = aes_gcm_encrypt(&key, &nonce, plaintext).unwrap();
        let decrypted = aes_gcm_decrypt(&key, &nonce, &ciphertext).unwrap();
        
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_gcm_different_keys() {
        let key1 = vec![0x00; 32];
        let key2 = vec![0xFF; 32];
        let nonce = vec![0x00; 12];
        let plaintext = b"test";
        
        let ct1 = aes_gcm_encrypt(&key1, &nonce, plaintext).unwrap();
        let ct2 = aes_gcm_encrypt(&key2, &nonce, plaintext).unwrap();
        
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_aes_gcm_different_nonces() {
        let key = vec![0x00; 32];
        let nonce1 = vec![0x00; 12];
        let nonce2 = vec![0x01; 12];
        let plaintext = b"test";
        
        let ct1 = aes_gcm_encrypt(&key, &nonce1, plaintext).unwrap();
        let ct2 = aes_gcm_encrypt(&key, &nonce2, plaintext).unwrap();
        
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_aes_gcm_empty_plaintext() {
        let key = vec![0x00; 32];
        let nonce = vec![0x00; 12];
        let plaintext = b"";
        
        let ciphertext = aes_gcm_encrypt(&key, &nonce, plaintext).unwrap();
        let decrypted = aes_gcm_decrypt(&key, &nonce, &ciphertext).unwrap();
        
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_gcm_auth_failure_tampered() {
        let key = vec![0x00; 32];
        let nonce = vec![0x00; 12];
        let plaintext = b"secret";
        
        let mut ciphertext = aes_gcm_encrypt(&key, &nonce, plaintext).unwrap();
        ciphertext[0] ^= 0xFF;
        
        let result = aes_gcm_decrypt(&key, &nonce, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_gcm_auth_failure_wrong_key() {
        let key1 = vec![0x00; 32];
        let key2 = vec![0xFF; 32];
        let nonce = vec![0x00; 12];
        let plaintext = b"secret";
        
        let ciphertext = aes_gcm_encrypt(&key1, &nonce, plaintext).unwrap();
        
        let result = aes_gcm_decrypt(&key2, &nonce, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_gcm_invalid_key_size() {
        let key = vec![0x00; 16];
        let nonce = vec![0x00; 12];
        let plaintext = b"test";
        
        let result = aes_gcm_encrypt(&key, &nonce, plaintext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CipherError::InvalidKeySize { expected: 32, actual: 16 });
    }

    #[test]
    fn test_aes_gcm_invalid_nonce_size() {
        let key = vec![0x00; 32];
        let nonce = vec![0x00; 8];
        let plaintext = b"test";
        
        let result = aes_gcm_encrypt(&key, &nonce, plaintext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CipherError::InvalidNonceSizeGcm);
    }

    #[test]
    fn test_aes_ctr_encrypt_decrypt() {
        let key = vec![0x00; 32];
        let nonce = vec![0x00; 8];
        let plaintext = b"Hello, CTR mode!";
        
        let ciphertext = aes_ctr_encrypt(&key, &nonce, plaintext).unwrap();
        let decrypted = aes_ctr_decrypt(&key, &nonce, &ciphertext).unwrap();
        
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_ctr_different_keys() {
        let key1 = vec![0x00; 32];
        let key2 = vec![0xFF; 32];
        let nonce = vec![0x00; 8];
        let plaintext = b"test";
        
        let ct1 = aes_ctr_encrypt(&key1, &nonce, plaintext).unwrap();
        let ct2 = aes_ctr_encrypt(&key2, &nonce, plaintext).unwrap();
        
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_aes_ctr_different_nonces() {
        let key = vec![0x00; 32];
        let nonce1 = vec![0x00; 8];
        let nonce2 = vec![0x01; 8];
        let plaintext = b"test";
        
        let ct1 = aes_ctr_encrypt(&key, &nonce1, plaintext).unwrap();
        let ct2 = aes_ctr_encrypt(&key, &nonce2, plaintext).unwrap();
        
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_aes_ctr_empty_plaintext() {
        let key = vec![0x00; 32];
        let nonce = vec![0x00; 8];
        let plaintext = b"";
        
        let ciphertext = aes_ctr_encrypt(&key, &nonce, plaintext).unwrap();
        let decrypted = aes_ctr_decrypt(&key, &nonce, &ciphertext).unwrap();
        
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_ctr_invalid_key_size() {
        let key = vec![0x00; 16];
        let nonce = vec![0x00; 8];
        let plaintext = b"test";
        
        let result = aes_ctr_encrypt(&key, &nonce, plaintext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CipherError::InvalidKeySize { expected: 32, actual: 16 });
    }

    #[test]
    fn test_aes_ctr_invalid_nonce_size() {
        let key = vec![0x00; 32];
        let nonce = vec![0x00; 4];
        let plaintext = b"test";
        
        let result = aes_ctr_encrypt(&key, &nonce, plaintext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CipherError::InvalidNonceSizeCtr);
    }

    #[test]
    fn test_aes_ctr_multiple_blocks() {
        let key = vec![0x42; 32];
        let nonce = vec![0xAB; 8];
        // Create a message larger than one AES block (16 bytes)
        let plaintext = b"This is a longer message that spans multiple AES blocks for testing purposes";
        
        let ciphertext = aes_ctr_encrypt(&key, &nonce, plaintext).unwrap();
        let decrypted = aes_ctr_decrypt(&key, &nonce, &ciphertext).unwrap();
        
        assert_eq!(decrypted, plaintext);
    }

    // AES-128-CBC tests
    #[test]
    fn test_aes_128_cbc_encrypt_decrypt() {
        let key = vec![0x00; 16];
        let iv = vec![0x00; 16];
        let plaintext = b"Hello, CBC mode!";
        
        let ciphertext = aes_128_cbc_encrypt(&key, &iv, plaintext).unwrap();
        let decrypted = aes_128_cbc_decrypt(&key, &iv, &ciphertext).unwrap();
        
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_128_cbc_different_keys() {
        let key1 = vec![0x00; 16];
        let key2 = vec![0xFF; 16];
        let iv = vec![0x00; 16];
        let plaintext = b"test";
        
        let ct1 = aes_128_cbc_encrypt(&key1, &iv, plaintext).unwrap();
        let ct2 = aes_128_cbc_encrypt(&key2, &iv, plaintext).unwrap();
        
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_aes_128_cbc_different_ivs() {
        let key = vec![0x00; 16];
        let iv1 = vec![0x00; 16];
        let iv2 = vec![0x01; 16];
        let plaintext = b"test";
        
        let ct1 = aes_128_cbc_encrypt(&key, &iv1, plaintext).unwrap();
        let ct2 = aes_128_cbc_encrypt(&key, &iv2, plaintext).unwrap();
        
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_aes_128_cbc_empty_plaintext() {
        let key = vec![0x00; 16];
        let iv = vec![0x00; 16];
        let plaintext = b"";
        
        let ciphertext = aes_128_cbc_encrypt(&key, &iv, plaintext).unwrap();
        let decrypted = aes_128_cbc_decrypt(&key, &iv, &ciphertext).unwrap();
        
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_128_cbc_invalid_key_size() {
        let key = vec![0x00; 32];
        let iv = vec![0x00; 16];
        let plaintext = b"test";
        
        let result = aes_128_cbc_encrypt(&key, &iv, plaintext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CipherError::InvalidKeySize { expected: 16, actual: 32 });
    }

    #[test]
    fn test_aes_128_cbc_invalid_iv_size() {
        let key = vec![0x00; 16];
        let iv = vec![0x00; 8];
        let plaintext = b"test";
        
        let result = aes_128_cbc_encrypt(&key, &iv, plaintext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CipherError::InvalidIvSizeCbc);
    }

    #[test]
    fn test_aes_128_cbc_single_block() {
        let key = vec![0x42; 16];
        let iv = vec![0xAB; 16];
        let plaintext = b"1234567890123456"; // Exactly 16 bytes (one block)
        
        let ciphertext = aes_128_cbc_encrypt(&key, &iv, plaintext).unwrap();
        let decrypted = aes_128_cbc_decrypt(&key, &iv, &ciphertext).unwrap();
        
        assert_eq!(decrypted, plaintext);
        assert_eq!(ciphertext.len(), 32); // One block + padding = 32 bytes
    }

    #[test]
    fn test_aes_128_cbc_multiple_blocks() {
        let key = vec![0x42; 16];
        let iv = vec![0xAB; 16];
        let plaintext = b"This is a longer message that spans multiple AES blocks for testing purposes";
        
        let ciphertext = aes_128_cbc_encrypt(&key, &iv, plaintext).unwrap();
        let decrypted = aes_128_cbc_decrypt(&key, &iv, &ciphertext).unwrap();
        
        assert_eq!(decrypted, plaintext);
    }

    // AES-256-CBC tests
    #[test]
    fn test_aes_256_cbc_encrypt_decrypt() {
        let key = vec![0x00; 32];
        let iv = vec![0x00; 16];
        let plaintext = b"Hello, AES-256-CBC mode!";
        
        let ciphertext = aes_256_cbc_encrypt(&key, &iv, plaintext).unwrap();
        let decrypted = aes_256_cbc_decrypt(&key, &iv, &ciphertext).unwrap();
        
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_256_cbc_different_keys() {
        let key1 = vec![0x00; 32];
        let key2 = vec![0xFF; 32];
        let iv = vec![0x00; 16];
        let plaintext = b"test";
        
        let ct1 = aes_256_cbc_encrypt(&key1, &iv, plaintext).unwrap();
        let ct2 = aes_256_cbc_encrypt(&key2, &iv, plaintext).unwrap();
        
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_aes_256_cbc_different_ivs() {
        let key = vec![0x00; 32];
        let iv1 = vec![0x00; 16];
        let iv2 = vec![0x01; 16];
        let plaintext = b"test";
        
        let ct1 = aes_256_cbc_encrypt(&key, &iv1, plaintext).unwrap();
        let ct2 = aes_256_cbc_encrypt(&key, &iv2, plaintext).unwrap();
        
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_aes_256_cbc_empty_plaintext() {
        let key = vec![0x00; 32];
        let iv = vec![0x00; 16];
        let plaintext = b"";
        
        let ciphertext = aes_256_cbc_encrypt(&key, &iv, plaintext).unwrap();
        let decrypted = aes_256_cbc_decrypt(&key, &iv, &ciphertext).unwrap();
        
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_256_cbc_invalid_key_size() {
        let key = vec![0x00; 16];
        let iv = vec![0x00; 16];
        let plaintext = b"test";
        
        let result = aes_256_cbc_encrypt(&key, &iv, plaintext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CipherError::InvalidKeySize { expected: 32, actual: 16 });
    }

    #[test]
    fn test_aes_256_cbc_invalid_iv_size() {
        let key = vec![0x00; 32];
        let iv = vec![0x00; 8];
        let plaintext = b"test";
        
        let result = aes_256_cbc_encrypt(&key, &iv, plaintext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CipherError::InvalidIvSizeCbc);
    }

    #[test]
    fn test_aes_256_cbc_single_block() {
        let key = vec![0x42; 32];
        let iv = vec![0xAB; 16];
        let plaintext = b"1234567890123456"; // Exactly 16 bytes (one block)
        
        let ciphertext = aes_256_cbc_encrypt(&key, &iv, plaintext).unwrap();
        let decrypted = aes_256_cbc_decrypt(&key, &iv, &ciphertext).unwrap();
        
        assert_eq!(decrypted, plaintext);
        assert_eq!(ciphertext.len(), 32); // One block + padding = 32 bytes
    }

    #[test]
    fn test_aes_256_cbc_multiple_blocks() {
        let key = vec![0x42; 32];
        let iv = vec![0xAB; 16];
        let plaintext = b"This is a longer message that spans multiple AES blocks for testing purposes";
        
        let ciphertext = aes_256_cbc_encrypt(&key, &iv, plaintext).unwrap();
        let decrypted = aes_256_cbc_decrypt(&key, &iv, &ciphertext).unwrap();
        
        assert_eq!(decrypted, plaintext);
    }
}