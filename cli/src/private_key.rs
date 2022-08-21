use crate::error::{MultiSigError, MultiSigResult};
use beserial::{ReadBytesExt, SerializingError};
use nimiq_hash::argon2kdf::{compute_argon2_kdf, Argon2Error};
use nimiq_hash::{Blake2bHasher, Hasher};
use nimiq_keys::{PrivateKey, PublicKey};

pub struct Secret {}

impl Secret {
    const SIZE: usize = 32;
    const SUPPORTED_PURPOSE: usize = 0x42000001;
    const ENCRYPTION_SALT_SIZE: usize = 16;
    const ENCRYPTION_CHECKSUM_SIZE: usize = 4;
    const ENCRYPTION_CHECKSUM_SIZE_V3: usize = 2;

    pub fn from_encrypted<R: ReadBytesExt>(
        reader: &mut R,
        key: &[u8],
    ) -> MultiSigResult<PrivateKey> {
        let version: u8 = reader.read_u8()?;
        let rounds_log: u8 = reader.read_u8()?;

        let rounds: u32 = 2u32.pow(rounds_log as u32);

        match version {
            1 => Secret::decrypt_v1(reader, key, rounds),
            2 => Secret::decrypt_v2(reader, key, rounds),
            3 => Secret::decrypt_v3(reader, key, rounds),
            _ => Err(SerializingError::InvalidEncoding)?,
        }
    }

    fn decrypt_v1<R: ReadBytesExt>(
        reader: &mut R,
        key: &[u8],
        rounds: u32,
    ) -> MultiSigResult<PrivateKey> {
        let mut ciphertext = [0u8; Secret::SIZE];
        reader.read_exact(&mut ciphertext)?;

        let mut salt = [0u8; Secret::ENCRYPTION_SALT_SIZE];
        reader.read_exact(&mut salt)?;

        let mut check = [0u8; Secret::ENCRYPTION_CHECKSUM_SIZE];
        reader.read_exact(&mut check)?;

        let plaintext = Secret::legacy_otp(&ciphertext, key, &salt, rounds)?;
        let private_key = PrivateKey::from_bytes(&plaintext)?;
        let public_key = PublicKey::from(&private_key);
        let h = Blake2bHasher::default().chain(&public_key).finish();
        if &h.as_ref()[..Secret::ENCRYPTION_CHECKSUM_SIZE] != &check {
            return Err(MultiSigError::InvalidPrivateKey);
        }

        Ok(private_key)
    }

    fn decrypt_v2<R: ReadBytesExt>(
        reader: &mut R,
        key: &[u8],
        rounds: u32,
    ) -> MultiSigResult<PrivateKey> {
        let mut ciphertext = [0u8; Secret::SIZE];
        reader.read_exact(&mut ciphertext)?;

        let mut salt = [0u8; Secret::ENCRYPTION_SALT_SIZE];
        reader.read_exact(&mut salt)?;

        let mut check = [0u8; Secret::ENCRYPTION_CHECKSUM_SIZE];
        reader.read_exact(&mut check)?;

        let plaintext = Secret::legacy_otp(&ciphertext, key, &salt, rounds)?;
        let h = Blake2bHasher::default().digest(&plaintext);
        if &h.as_ref()[..Secret::ENCRYPTION_CHECKSUM_SIZE] != &check {
            return Err(MultiSigError::InvalidPrivateKey);
        }

        let private_key = PrivateKey::from_bytes(&plaintext)?;
        Ok(private_key)
    }

    fn decrypt_v3<R: ReadBytesExt>(
        reader: &mut R,
        key: &[u8],
        rounds: u32,
    ) -> MultiSigResult<PrivateKey> {
        let mut salt = [0u8; Secret::ENCRYPTION_SALT_SIZE];
        reader.read_exact(&mut salt)?;

        let mut ciphertext =
            [0u8; Secret::ENCRYPTION_CHECKSUM_SIZE_V3 + /*purpose*/ 4 + Secret::SIZE];
        reader.read_exact(&mut ciphertext)?;

        let mut check = Secret::otp(&ciphertext, key, &salt, rounds)?;
        let payload = check.split_off(Secret::ENCRYPTION_CHECKSUM_SIZE_V3);
        let checksum = Blake2bHasher::default().digest(&payload);
        if &checksum.as_ref()[..Secret::ENCRYPTION_CHECKSUM_SIZE_V3] != &check {
            return Err(MultiSigError::InvalidPrivateKey);
        }

        let purpose_id: usize = (payload[0] as usize) << 24
            | (payload[1] as usize) << 16
            | (payload[2] as usize) << 8
            | (payload[3] as usize);
        if purpose_id != Secret::SUPPORTED_PURPOSE {
            return Err(MultiSigError::InvalidPrivateKey);
        }

        let private_key = PrivateKey::from_bytes(&payload[4..])?;
        Ok(private_key)
    }

    fn legacy_otp(secret: &[u8], key: &[u8], salt: &[u8], rounds: u32) -> MultiSigResult<Vec<u8>> {
        let mut derived_key = legacy_kdf(key, salt, rounds, secret.len())?;
        xor(&mut derived_key, secret);
        Ok(derived_key)
    }

    fn otp(secret: &[u8], key: &[u8], salt: &[u8], rounds: u32) -> MultiSigResult<Vec<u8>> {
        let mut derived_key = kdf(key, salt, rounds, secret.len())?;
        xor(&mut derived_key, secret);
        Ok(derived_key)
    }
}

fn xor(key: &mut [u8], secret: &[u8]) {
    assert_eq!(secret.len(), key.len());
    for (a, b) in key.iter_mut().zip(secret.iter()) {
        *a ^= b;
    }
}

fn legacy_kdf(
    key: &[u8],
    salt: &[u8],
    rounds: u32,
    out_len: usize,
) -> Result<Vec<u8>, Argon2Error> {
    let mut out = compute_argon2_kdf(key, salt, 1, out_len)?;
    for _ in 0..rounds {
        out = compute_argon2_kdf(&out, salt, 1, out_len)?;
    }
    Ok(out)
}

fn kdf(key: &[u8], salt: &[u8], rounds: u32, out_len: usize) -> Result<Vec<u8>, Argon2Error> {
    compute_argon2_kdf(key, salt, rounds, out_len)
}
