use base64;
use hex::FromHex;
use nimiq_keys::multisig::{Commitment, CommitmentPair, PartialSignature};
use nimiq_keys::{Address, KeyPair, PrivateKey, PublicKey};
use std::io;
use std::io::Write;

use multisig_lib::multisig::{
    combine_public_keys, compute_address, partially_sign, partially_verify,
};

use crate::config::Config;
use crate::error::*;
use crate::private_key::Secret;
use crate::utils::{read_bool, read_line, read_usize};

use curve25519_dalek::scalar::Scalar;

pub struct MultiSig {
    pub secret: Vec<u8>,
    pub private_key: PrivateKey,
    pub num_signers: usize,
    pub public_keys: Vec<PublicKey>,
}

impl MultiSig {
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(&self.private_key)
    }

    pub fn new(
        secret: Vec<u8>,
        private_key: PrivateKey,
        num_signers: usize,
        public_keys: Vec<PublicKey>,
    ) -> Self {
        MultiSig {
            secret,
            private_key,
            num_signers,
            public_keys,
        }
    }

    pub fn from_terminal() -> MultiSigResult<Self> {
        println!("🤓 Have you already imported your MultiSig and want to load the configuration? yes/[no]");
        let import = read_bool()?;

        if import {
            println!("🗄 Please enter the file name for the configuration file:");
            let filename = read_line()?;
            if let Ok(multisig) = Self::from_file(&filename) {
                return Ok(multisig);
            }

            println!("😵 Could not open a file at {}.", filename);
            println!("  Starting new MultiSig configuration process instead.");
        }

        println!();
        println!("🔐 Let's start with your private key.");
        let secret = MultiSig::import_access_file()?;
        let private_key = MultiSig::unlock_secret(&secret)?;
        let public_key = PublicKey::from(&private_key);

        println!();
        println!("ℹ️  Next, I need some information about the MultiSig wallet.");
        println!("👨‍👩‍👧‍👦 Who are the owners of the wallet? Please enter all public keys line-by-line (excluding yours).");
        println!("  Once you're done, simply enter: done");
        let mut public_keys: Vec<PublicKey> = vec![];
        loop {
            print!("[{}]", public_keys.len() + 1);
            let owner_pk = read_line()?;
            let owner_pk = owner_pk.trim();

            // Break on done.
            if owner_pk == "done" {
                break;
            }

            if let Ok(owner_pk) = FromHex::from_hex(owner_pk) {
                if owner_pk != public_key {
                    public_keys.push(owner_pk);
                }
            } else {
                println!("🤨 Oops, seems like you're doing something wrong. This is not a valid public key. Try again!");
            }
        }

        println!(
            "👨‍👩‍👧‍👦 Looks like there are {} owners.",
            public_keys.len() + 1
        );
        println!("  How many of them must sign a transaction?");
        let num_signers = read_usize()?;
        println!("  So, {} are required for signing.", num_signers);

        let wallet = MultiSig::new(secret, private_key, num_signers, public_keys);

        println!("🤓 Do you want to store everything in a configuration file for easier access (your private key is encrypted)? yes/[no]");
        let store = read_bool()?;
        if store {
            println!("🗄  Okay, so where should we store the file? Please give the full file name (e.g., mywallet.toml):");
            let filename = read_line()?;
            let config = Config::from(&wallet);
            config.to_file(&filename)?;
        }

        Ok(wallet)
    }

    fn import_access_file() -> MultiSigResult<Vec<u8>> {
        println!(
            "🗄  Please enter the path to your account access file (the png with the QR code):"
        );
        let filename = read_line()?;
        let secret = import_secret_from_access_file(&filename)?;

        Ok(secret)
    }

    fn unlock_secret(secret: &[u8]) -> MultiSigResult<PrivateKey> {
        println!("🔑 Please enter the password for your access file:");
        print!("> ");
        io::stdout().flush()?;
        let password = rpassword::read_password()?;
        let private_key = Secret::from_encrypted(&mut &*secret, password.as_ref())?;
        let public_key = PublicKey::from(&private_key);

        println!("🔓 Great, we've unlocked your key! Your public key is:");
        println!("{}", public_key);

        Ok(private_key)
    }

    pub fn from_file(filename: &str) -> MultiSigResult<Self> {
        let mut config = Config::from_file(filename)?;

        let secret = if let Some(ref secret) = config.encrypted_private_key {
            base64::decode(secret)?
        } else {
            println!("🔐 It looks like the configuration does not contain your keypair.");
            MultiSig::import_access_file()?
        };

        let private_key = MultiSig::unlock_secret(&secret)?;
        let public_keys = config
            .public_keys
            .iter()
            .map(|pk| PublicKey::from_hex(pk))
            .collect::<Result<_, _>>()?;

        if config.encrypted_private_key.is_none() {
            println!("🤓 Do you want to store your encrypted private key in the configuration for easier access? yes/[no]");
            let store = read_bool()?;
            if store {
                config.encrypted_private_key = Some(base64::encode(&secret));
                config.to_file(filename)?;
            }
        }

        let wallet = MultiSig::new(secret, private_key, config.num_signers, public_keys);

        Ok(wallet)
    }

    pub fn public_keys(&self) -> Vec<PublicKey> {
        let mut public_keys = self.public_keys.clone();
        public_keys.push(self.public_key());
        public_keys.sort();

        combine_public_keys(&public_keys, self.num_signers)
    }

    pub fn address(&self) -> Address {
        let combined_public_keys = self.public_keys();
        compute_address(&combined_public_keys)
    }

    pub fn partially_sign(
        &self,
        public_keys: &[PublicKey],
        aggregated_commitment: &Commitment,
        b: Scalar,
        own_commitment_pairs: &[CommitmentPair],
        data: &[u8],
    ) -> PartialSignature {
        // And delinearize them.
        let key_pair = KeyPair {
            public: self.public_key().clone(),
            private: self.private_key.clone(),
        };

        let partial_signature = partially_sign(
            public_keys,
            aggregated_commitment,
            &b,
            own_commitment_pairs,
            &key_pair,
            data,
        );

        assert!(partially_verify(
            public_keys,
            aggregated_commitment,
            &b,
            &self.public_key(),
            own_commitment_pairs
                .iter()
                .map(|pair| *pair.commitment())
                .collect::<Vec<Commitment>>()
                .as_slice(),
            &partial_signature,
            data
        ));

        partial_signature
    }
}

impl<'a> From<&'a MultiSig> for Config {
    fn from(wallet: &'a MultiSig) -> Self {
        Config {
            encrypted_private_key: Some(base64::encode(&wallet.secret)),
            num_signers: wallet.num_signers,
            public_keys: wallet.public_keys.iter().map(|pk| pk.to_hex()).collect(),
        }
    }
}

impl From<MultiSig> for Config {
    fn from(wallet: MultiSig) -> Self {
        Config::from(&wallet)
    }
}

fn import_secret_from_access_file(filename: &str) -> MultiSigResult<Vec<u8>> {
    let img = image::open(filename)?;
    // Convert to gray.
    let img_gray = img.into_luma8();

    // Create a decoder.
    let mut decoder = quircs::Quirc::default();

    // Identify all qr codes.
    let codes = decoder.identify(
        img_gray.width() as usize,
        img_gray.height() as usize,
        &img_gray,
    );

    // Try reading QR codes.
    for code in codes {
        let code = code?;
        let decoded = code.decode()?;
        let payload = std::str::from_utf8(&decoded.payload)?;
        let buf = base64::decode(payload)?;

        return Ok(buf);
    }
    Err(MultiSigError::InvalidAccessFile)
}
