// mofold-core/src/envelope.rs
//
// 64-byte Binary Desert Protocol Envelope Header
// Wire-compatible with the original TypeScript BDP implementation.
//
// Layout:
//   Byte  0      : Protocol version (0x02 for BDP v2 / MofoldZiplog)
//   Byte  1      : Blob type  (0x01 VAULT | 0x02 FOLD | 0x03 ROOM | 0x04 INVITE | 0x05 LOG)
//   Bytes 2-33   : AdminHash  — SHA-256(adminToken) [32 bytes]
//   Bytes 34-49  : Salt1      — random 16-byte salt for GCM key derivation
//   Bytes 50-61  : IV1        — random 12-byte IV for AES-256-GCM
//   Bytes 62-63  : PayloadLen — u16 big-endian (0 = use total blob length - ENVELOPE_SIZE)
//   Bytes 64+    : Encrypted payload: Salt2(16) + IV2(16) + CBC ciphertext

use zeroize::Zeroize;
use crate::error::BdpError;

pub const ENVELOPE_SIZE: usize = 64;
pub const PROTOCOL_VERSION: u8  = 0x02;

/// All valid blob types. LOG (0x05) is new in BDP v2 for MofoldZiplog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BlobType {
    Vault  = 0x01,
    Fold   = 0x02,
    Room   = 0x03,
    Invite = 0x04,
    Log    = 0x05,   // ← MofoldZiplog log entry
}

impl TryFrom<u8> for BlobType {
    type Error = BdpError;
    fn try_from(b: u8) -> Result<Self, Self::Error> {
        match b {
            0x01 => Ok(BlobType::Vault),
            0x02 => Ok(BlobType::Fold),
            0x03 => Ok(BlobType::Room),
            0x04 => Ok(BlobType::Invite),
            0x05 => Ok(BlobType::Log),
            other => Err(BdpError::InvalidBlobType(other)),
        }
    }
}

/// Parsed envelope header.
#[derive(Debug, Clone, Zeroize)]
pub struct Envelope {
    pub version:    u8,
    pub blob_type:  u8,          // stored as raw u8 to allow Zeroize
    pub admin_hash: [u8; 32],
    pub salt1:      [u8; 16],
    pub iv1:        [u8; 12],
    pub payload_len: u16,
}

impl Envelope {
    /// Pack a new envelope together with an already-encrypted payload into a
    /// single contiguous byte buffer ready for storage.
    pub fn pack(
        blob_type:   BlobType,
        admin_hash:  &[u8; 32],
        salt1:       &[u8; 16],
        iv1:         &[u8; 12],
        payload:     &[u8],
    ) -> Vec<u8> {
        // Use 0 as sentinel meaning "read to end" for payloads > 65535 bytes.
        let payload_len: u16 = if payload.len() > 0xFFFF { 0 } else { payload.len() as u16 };
        let mut out = Vec::with_capacity(ENVELOPE_SIZE + payload.len());

        out.push(PROTOCOL_VERSION);
        out.push(blob_type as u8);
        out.extend_from_slice(admin_hash);   // bytes  2-33
        out.extend_from_slice(salt1);         // bytes 34-49
        out.extend_from_slice(iv1);           // bytes 50-61
        out.push((payload_len >> 8) as u8);  // byte  62
        out.push((payload_len & 0xFF) as u8);// byte  63
        out.extend_from_slice(payload);       // bytes 64+

        out
    }

    /// Unpack a raw blob into its header and payload. Does NOT decrypt.
    pub fn unpack(blob: &[u8]) -> Result<(Envelope, &[u8]), BdpError> {
        if blob.len() < ENVELOPE_SIZE {
            return Err(BdpError::EnvelopeTooSmall(ENVELOPE_SIZE, blob.len()));
        }

        let version   = blob[0];
        let blob_type = blob[1];
        let payload_len = u16::from_be_bytes([blob[62], blob[63]]);
        let payload = if payload_len > 0 {
            let end = ENVELOPE_SIZE + payload_len as usize;
            if end > blob.len() {
                return Err(BdpError::EnvelopeTooSmall(end, blob.len()));
            }
            &blob[ENVELOPE_SIZE..end]
        } else {
            &blob[ENVELOPE_SIZE..]
        };

        let mut admin_hash = [0u8; 32];
        let mut salt1      = [0u8; 16];
        let mut iv1        = [0u8; 12];
        admin_hash.copy_from_slice(&blob[2..34]);
        salt1.copy_from_slice(&blob[34..50]);
        iv1.copy_from_slice(&blob[50..62]);

        Ok((Envelope { version, blob_type, admin_hash, salt1, iv1, payload_len }, payload))
    }

    /// Convenience: get blob_type as the enum variant.
    pub fn typed_blob_type(&self) -> Result<BlobType, BdpError> {
        BlobType::try_from(self.blob_type)
    }

    /// True when the admin hash is all zeros (open-write blob — shared room manifests).
    pub fn is_zero_admin_hash(&self) -> bool {
        self.admin_hash.iter().all(|&b| b == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_unpack_roundtrip() {
        let admin_hash = [0xAA; 32];
        let salt1      = [0xBB; 16];
        let iv1        = [0xCC; 12];
        let payload    = b"hello encrypted world";

        let blob = Envelope::pack(BlobType::Log, &admin_hash, &salt1, &iv1, payload);
        assert_eq!(blob.len(), ENVELOPE_SIZE + payload.len());

        let (hdr, recovered) = Envelope::unpack(&blob).unwrap();
        assert_eq!(hdr.version, PROTOCOL_VERSION);
        assert_eq!(hdr.blob_type, BlobType::Log as u8);
        assert_eq!(hdr.admin_hash, admin_hash);
        assert_eq!(hdr.salt1, salt1);
        assert_eq!(hdr.iv1, iv1);
        assert_eq!(recovered, payload);
    }

    #[test]
    fn too_small_blob_errors() {
        let blob = [0u8; 10];
        assert!(matches!(Envelope::unpack(&blob), Err(BdpError::EnvelopeTooSmall(_, _))));
    }
}
