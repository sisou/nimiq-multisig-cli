use base64;
use beserial;
use block_modes;
use hex;
use image;
use nimiq_hash::argon2kdf::Argon2Error;
use nimiq_keys::{KeysError, ParseError};
use quircs;
use std::{io, str};
use thiserror::Error;
use toml;

#[derive(Error, Debug)]
pub enum MultiSigError {
    #[error("IO Error: {0}")]
    Io(#[from] io::Error),
    #[error("Image Error: {0}")]
    Image(#[from] image::ImageError),
    #[error("TOML Deserialization Error: {0}")]
    TomlDe(#[from] toml::de::Error),
    #[error("TOML Serialization Error: {0}")]
    TomlSer(#[from] toml::ser::Error),
    #[error("QR Decode Error: {0}")]
    QrDecode(#[from] quircs::DecodeError),
    #[error("QR Extract Error: {0}")]
    QrExtraction(#[from] quircs::ExtractError),
    #[error("UTF8 Error: {0}")]
    Utf8(#[from] str::Utf8Error),
    #[error("Serializing Error: {0}")]
    Beserial(#[from] beserial::SerializingError),
    #[error("Base64 Error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("Argon2 Error: {0}")]
    Argon2(#[from] Argon2Error),
    #[error("Pbkdf2 Error")]
    Pbkdf2,
    #[error("Keys Error: {0}")]
    Ed25519(#[from] KeysError),
    #[error("Invalid key/IV Length: {0}")]
    Cipher(#[from] block_modes::InvalidKeyIvLength),
    #[error("Block Mode Error: {0}")]
    Decryption(#[from] block_modes::BlockModeError),
    #[error("Parse Error: {0}")]
    Hex(#[from] ParseError),
    #[error("FromHex Error: {0}")]
    FromHex(#[from] hex::FromHexError),
    #[error("Missing commitments")]
    MissingCommitments,
    #[error("Invalid private key")]
    InvalidPrivateKey,
    #[error("Invalid access file")]
    InvalidAccessFile,
    #[error("Missing Transaction")]
    MissingTransaction,
}

pub type MultiSigResult<T> = Result<T, MultiSigError>;
