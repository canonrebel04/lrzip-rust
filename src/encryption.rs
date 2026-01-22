use anyhow::{anyhow, Result};
use aes::cipher::{BlockEncryptMut, BlockDecryptMut, KeyIvInit};
use cbc::{Encryptor, Decryptor};
use pbkdf2::pbkdf2;
use hmac::Hmac;
use sha2::Sha256;

// Type aliases for AES-128-CBC
type Aes128CbcEnc = Encryptor<aes::Aes128>;
type Aes128CbcDec = Decryptor<aes::Aes128>;

// Constants
const _SALT_LEN: usize = 8;
const KEY_LEN: usize = 16; // AES-128
const IV_LEN: usize = 16;  // AES block size
const ITERATIONS: u32 = 10_000; // Reasonable default, verify with lrzip later if possible

pub struct EncryptionEngine {
    key: [u8; KEY_LEN],
    iv: [u8; IV_LEN],
}

impl EncryptionEngine {
    pub fn new(password: &str, salt: &[u8; 8]) -> Self {
        let mut key = [0u8; KEY_LEN];
        // Note: IV is often derived or part of the salt. 
        // In lrzip scheme, we need to check if IV is salt + padding or derived.
        // For now, we will derive 32 bytes (Key + IV) using PBKDF2.
        
        let mut key_iv = [0u8; KEY_LEN + IV_LEN];
        pbkdf2::<Hmac<Sha256>>(
            password.as_bytes(),
            salt,
            ITERATIONS,
            &mut key_iv
        ).expect("pbkdf2");

        let mut iv = [0u8; IV_LEN];
        key.copy_from_slice(&key_iv[0..16]);
        iv.copy_from_slice(&key_iv[16..32]);

        Self { key, iv }
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        // PKCS7 padding is standard for CBC
        let mut buffer = vec![0u8; data.len() + IV_LEN]; // Ensure enough space
        buffer[..data.len()].copy_from_slice(data);
        
        let _header_salt = &self.iv[0..8]; // Not used here directly, but structure needs IV 
        
        let encryptor = Aes128CbcEnc::new(&self.key.into(), &self.iv.into());
        // Writes ciphertext into buffer, returns used slice
        let ct_len = encryptor.encrypt_padded_b2b_mut::<cbc::cipher::block_padding::Pkcs7>(
            data,
            &mut buffer
        ).map_err(|e| anyhow!("encryption error: {}", e))?.len();
        
        buffer.truncate(ct_len);
        Ok(buffer)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut buffer = data.to_vec();
        
        let decryptor = Aes128CbcDec::new(&self.key.into(), &self.iv.into());
        let pt_len = decryptor.decrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(
            &mut buffer
        ).map_err(|e| anyhow!("decryption error: {}", e))?.len();
        
        buffer.truncate(pt_len);
        Ok(buffer)
    }
}
