//! Direct Message Cryptography
//!
//! Implements Noise Protocol IK pattern for encrypted direct messages between friends.
//! - DM Channel ID: SHA256(min(pubA, pubB) || max(pubA, pubB))
//! - Noise Pattern: Noise_IK_25519_ChaChaPoly_SHA256

use sha2::{Sha256, Digest};
use snow::Builder;
use std::cmp::Ordering;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};

/// Derive DM channel ID from two Ed25519 public keys
/// 
/// Formula: SHA256(min(pubA, pubB) || max(pubA, pubB))
/// This ensures both peers compute the same channel ID
pub fn derive_dm_channel_id(pub_a: &[u8; 32], pub_b: &[u8; 32]) -> [u8; 32] {
    let (min_pub, max_pub) = match pub_a.cmp(pub_b) {
        Ordering::Less | Ordering::Equal => (pub_a, pub_b),
        Ordering::Greater => (pub_b, pub_a),
    };

    let mut hasher = Sha256::new();
    hasher.update(min_pub);
    hasher.update(max_pub);
    hasher.finalize().into()
}

/// Noise Protocol state for a DM channel
/// 
/// This will be used in Phase 5+ for persistent session management
#[allow(dead_code)] // Will be used in Phase 5+ (Transport layer)
pub struct DmCryptoState {
    handshake_state: Option<snow::HandshakeState>,
    transport_state: Option<snow::TransportState>,
    channel_id: [u8; 32],
}

#[allow(dead_code)] // Will be used in Phase 5+
impl DmCryptoState {
    /// Create a new DM crypto state from completed handshake
    pub fn from_transport(transport: snow::TransportState, channel_id: [u8; 32]) -> Self {
        Self {
            handshake_state: None,
            transport_state: Some(transport),
            channel_id,
        }
    }

    /// Encrypt a message
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let transport = self.transport_state.as_mut()
            .ok_or("Transport state not initialized")?;

        let mut ciphertext = vec![0u8; plaintext.len() + 16]; // +16 for MAC
        let len = transport.write_message(plaintext, &mut ciphertext)
            .map_err(|e| format!("Encryption failed: {}", e))?;

        ciphertext.truncate(len);
        Ok(ciphertext)
    }

    /// Decrypt a message
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let transport = self.transport_state.as_mut()
            .ok_or("Transport state not initialized")?;

        let mut plaintext = vec![0u8; ciphertext.len()];
        let len = transport.read_message(ciphertext, &mut plaintext)
            .map_err(|e| format!("Decryption failed: {}", e))?;

        plaintext.truncate(len);
        Ok(plaintext)
    }

    /// Get the channel ID
    pub fn channel_id(&self) -> &[u8; 32] {
        &self.channel_id
    }
}

/// Perform Noise IK handshake as initiator and return transport state
/// 
/// IK pattern: Initiator sends message 1, Responder sends message 2
/// Both sides know each other's static public keys in advance
/// 
/// This will be used in Phase 5+ for network-based handshakes
#[allow(dead_code)] // Will be used in Phase 5+ (Transport layer)
pub fn perform_ik_handshake_initiator(
    local_x25519_secret: &[u8; 32],
    remote_x25519_public: &[u8; 32],
) -> Result<(Vec<u8>, snow::TransportState), String> {
    let builder = Builder::new("Noise_IK_25519_ChaChaPoly_SHA256".parse()
        .map_err(|e| format!("Invalid noise pattern: {}", e))?);

    let mut handshake = builder
        .local_private_key(local_x25519_secret)
        .map_err(|e| format!("Failed to set local private key: {}", e))?
        .remote_public_key(remote_x25519_public)
        .map_err(|e| format!("Failed to set remote public key: {}", e))?
        .build_initiator()
        .map_err(|e| format!("Failed to build initiator: {}", e))?;

    // Write message 1 (initiator -> responder)
    let mut msg1 = vec![0u8; 1024];
    let msg1_len = handshake.write_message(&[], &mut msg1)
        .map_err(|e| format!("Handshake message 1 write failed: {}", e))?;
    msg1.truncate(msg1_len);

    // Read message 2 (responder -> initiator)
    // Note: In real usage, this would come over the network
    // For Phase 3, we assume message 2 is provided separately
    // This function returns message 1 and expects message 2 to be processed separately
    
    // For now, return the handshake state - caller will need to complete with message 2
    // Actually, let's create a helper that does the full handshake with both messages
    Err("IK handshake requires two-way communication. Use perform_full_ik_handshake instead.".to_string())
}

/// Perform full Noise IK handshake (for testing/internal use)
/// 
/// This simulates both sides of the handshake for Phase 3 testing
pub fn perform_full_ik_handshake(
    initiator_x25519_secret: &[u8; 32],
    responder_x25519_secret: &[u8; 32],
    initiator_x25519_public: &[u8; 32],
    responder_x25519_public: &[u8; 32],
) -> Result<(snow::TransportState, snow::TransportState), String> {
    let _builder = Builder::new("Noise_IK_25519_ChaChaPoly_SHA256".parse()
        .map_err(|e| format!("Invalid noise pattern: {}", e))?);

    // Initiator side
    let init_builder = Builder::new("Noise_IK_25519_ChaChaPoly_SHA256".parse()
        .map_err(|e| format!("Invalid noise pattern: {}", e))?);
    let mut init_handshake = init_builder
        .local_private_key(initiator_x25519_secret)
        .map_err(|e| format!("Failed to set initiator private key: {}", e))?
        .remote_public_key(responder_x25519_public)
        .map_err(|e| format!("Failed to set responder public key: {}", e))?
        .build_initiator()
        .map_err(|e| format!("Failed to build initiator: {}", e))?;

    // Responder side
    let resp_builder = Builder::new("Noise_IK_25519_ChaChaPoly_SHA256".parse()
        .map_err(|e| format!("Invalid noise pattern: {}", e))?);
    let mut resp_handshake = resp_builder
        .local_private_key(responder_x25519_secret)
        .map_err(|e| format!("Failed to set responder private key: {}", e))?
        .remote_public_key(initiator_x25519_public)
        .map_err(|e| format!("Failed to set initiator public key: {}", e))?
        .build_responder()
        .map_err(|e| format!("Failed to build responder: {}", e))?;

    // Initiator sends message 1
    let mut msg1 = vec![0u8; 1024];
    let msg1_len = init_handshake.write_message(&[], &mut msg1)
        .map_err(|e| format!("Handshake message 1 write failed: {}", e))?;
    msg1.truncate(msg1_len);

    // Responder reads message 1 and sends message 2
    let mut msg2_buf = vec![0u8; 1024];
    resp_handshake.read_message(&msg1, &mut msg2_buf)
        .map_err(|e| format!("Handshake message 1 read failed: {}", e))?;

    let mut msg2 = vec![0u8; 1024];
    let msg2_len = resp_handshake.write_message(&[], &mut msg2)
        .map_err(|e| format!("Handshake message 2 write failed: {}", e))?;
    msg2.truncate(msg2_len);

    // Initiator reads message 2
    let mut dummy = vec![0u8; 1024];
    init_handshake.read_message(&msg2, &mut dummy)
        .map_err(|e| format!("Handshake message 2 read failed: {}", e))?;

    // Both sides enter transport mode
    let init_transport = init_handshake.into_transport_mode()
        .map_err(|e| format!("Failed to enter transport mode (initiator): {}", e))?;
    let resp_transport = resp_handshake.into_transport_mode()
        .map_err(|e| format!("Failed to enter transport mode (responder): {}", e))?;

    Ok((init_transport, resp_transport))
}

/// DM encryption session (maintains transport state after handshake)
/// 
/// This session is created after a successful Noise IK handshake.
/// In Phase 5+, the handshake will be performed over the network transport.
pub struct DmSession {
    transport: snow::TransportState,
    #[allow(dead_code)] // Will be used in Phase 5+ for routing
    channel_id: [u8; 32],
}

impl DmSession {
    /// Create a session from an established transport state
    /// 
    /// The transport state should be obtained after completing a Noise IK handshake.
    pub fn from_transport(transport: snow::TransportState, channel_id: [u8; 32]) -> Self {
        Self {
            transport,
            channel_id,
        }
    }

    /// Encrypt a message using this session
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let mut ciphertext = vec![0u8; plaintext.len() + 16]; // +16 for MAC
        let len = self.transport.write_message(plaintext, &mut ciphertext)
            .map_err(|e| format!("Encryption failed: {}", e))?;
        ciphertext.truncate(len);
        Ok(ciphertext)
    }

    /// Decrypt a message using this session
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let mut plaintext = vec![0u8; ciphertext.len()];
        let len = self.transport.read_message(ciphertext, &mut plaintext)
            .map_err(|e| format!("Decryption failed: {}", e))?;
        plaintext.truncate(len);
        Ok(plaintext)
    }

    /// Get the channel ID
    /// 
    /// This will be used in Phase 5+ for routing messages to the correct channel
    #[allow(dead_code)] // Will be used in Phase 5+ for routing
    pub fn channel_id(&self) -> &[u8; 32] {
        &self.channel_id
    }
}

/// Encrypt a DM message using an established session
/// 
/// This is the Phase 3 API. The session should be created after handshake completion.
/// In Phase 5+, handshake will be performed over network transport.
#[allow(dead_code)] // Will be used in Phase 5+ (Transport layer)
pub fn encrypt_dm_message(session: &mut DmSession, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    session.encrypt(plaintext)
}

/// Decrypt a DM message using an established session
#[allow(dead_code)] // Will be used in Phase 5+ (Transport layer)
pub fn decrypt_dm_message(session: &mut DmSession, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    session.decrypt(ciphertext)
}

/// Test helper: Create a session by simulating both sides of handshake
/// 
/// This is for Phase 3 testing only. In production, handshake happens over network.
pub fn create_test_session(
    local_ed25519: &[u8; 32],
    local_x25519_secret: &[u8; 32],
    local_x25519_public: &[u8; 32],
    remote_ed25519: &[u8; 32],
    remote_x25519_secret: &[u8; 32],
    remote_x25519_public: &[u8; 32],
    is_initiator: bool,
) -> Result<DmSession, String> {
    let channel_id = derive_dm_channel_id(local_ed25519, remote_ed25519);
    
    let (init_transport, resp_transport) = perform_full_ik_handshake(
        local_x25519_secret,
        remote_x25519_secret,
        local_x25519_public,
        remote_x25519_public,
    )?;

    let transport = if is_initiator {
        init_transport
    } else {
        resp_transport
    };

    Ok(DmSession::from_transport(transport, channel_id))
}

/// Get DM channel ID as hex string
pub fn dm_channel_id_to_hex(channel_id: &[u8; 32]) -> String {
    hex::encode(channel_id)
}

/// Deterministic encryption for self-messaging
/// Uses ChaCha20Poly1305 with a key derived from channel_id and a nonce from message_id
pub fn encrypt_self_message(channel_id: &[u8; 32], message_id: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    // Derive encryption key from channel_id
    let mut hasher = Sha256::new();
    hasher.update(b"self_msg_key");
    hasher.update(channel_id);
    let key_bytes: [u8; 32] = hasher.finalize().into();
    let key = chacha20poly1305::Key::from_slice(&key_bytes);
    
    // Use message_id as nonce (first 12 bytes)
    // If message_id is less than 12 bytes, pad with zeros
    let mut nonce_bytes = [0u8; 12];
    let copy_len = std::cmp::min(12, message_id.len());
    nonce_bytes[0..copy_len].copy_from_slice(&message_id[0..copy_len]);
    let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
    
    let cipher = ChaCha20Poly1305::new(key);
    cipher.encrypt(nonce, plaintext)
        .map_err(|e| format!("Encryption failed: {}", e))
}

/// Deterministic decryption for self-messaging
pub fn decrypt_self_message(channel_id: &[u8; 32], message_id: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    // Derive encryption key from channel_id (same as encryption)
    let mut hasher = Sha256::new();
    hasher.update(b"self_msg_key");
    hasher.update(channel_id);
    let key_bytes: [u8; 32] = hasher.finalize().into();
    let key = chacha20poly1305::Key::from_slice(&key_bytes);
    
    // Use message_id as nonce (first 12 bytes)
    // If message_id is less than 12 bytes, pad with zeros
    let mut nonce_bytes = [0u8; 12];
    let copy_len = std::cmp::min(12, message_id.len());
    nonce_bytes[0..copy_len].copy_from_slice(&message_id[0..copy_len]);
    let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
    
    let cipher = ChaCha20Poly1305::new(key);
    cipher.decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption failed: {}", e))
}

