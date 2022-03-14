use base64;
use hex::FromHex;
use itertools::Itertools;
use nimiq_hash::Blake2bHasher;
use nimiq_keys::{Address, PrivateKey, PublicKey}; //, KeyPair
// use nimiq_keys::multisig::{RandomSecret, Commitment, PartialSignature};
use nimiq_utils::merkle::compute_root_from_content;
use std::io;
use std::io::Write;

use crate::config::Config;
use crate::error::*;
use crate::private_key::Secret;
use crate::public_key::DelinearizedPublicKey;
use crate::utils::{read_bool, read_line, read_usize};

pub struct MultiSig {
    pub secret: Vec<u8>,
    pub private_key: PrivateKey,
    pub num_signers: usize,
    pub public_keys: Vec<PublicKey>,
}


// impl std::fmt::Display for MultiSig {
//     fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
//         write!(f, "(value secret: {:?}, value private_key: {:?}), value num_signers: {}, value public_keys: {:?}", 
//         self.secret, self.private_key, self.num_signers, self.public_keys)
//     }
// }


impl MultiSig {
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(&self.private_key)
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

        let wallet = MultiSig {
            secret,
            private_key,
            num_signers,
            public_keys,
        };

        // println!("{}", wallet);

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

        let wallet = MultiSig {
            secret,
            private_key,
            num_signers: config.num_signers,
            public_keys,
        };

        Ok(wallet)
    }

    pub fn public_keys(&self) -> MultiSigResult<Vec<PublicKey>> {
        let public_key = PublicKey::from(&self.private_key);
        let mut public_keys = self.public_keys.clone();
        public_keys.push(public_key);
        public_keys.sort();

        // Calculate combinations.
        let combinations = public_keys.into_iter().combinations(self.num_signers);
        let mut multisig_keys: Vec<PublicKey> = combinations
            .map(|combination| DelinearizedPublicKey::sum_delinearized(&combination))
            .collect();
        multisig_keys.sort();
        Ok(multisig_keys)
    }

    pub fn address(&self) -> MultiSigResult<Address> {
        let multisig_keys = self.public_keys()?;

        // Calculate address.
        let merkle_root = compute_root_from_content::<Blake2bHasher, _>(&multisig_keys);
        let address = Address::from(merkle_root);
        Ok(address)
    }

    // pub fn partially_sign(&self, public_keys: &[PublicKey], secret: &RandomSecret, commitments: &[Commitment], data: &[u8]) -> PartialSignature {
    //     let kp = KeyPair::from(self.private_key.clone());
    //     kp.partial_sign(public_keys, secret, commitments, data).0
    // }
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
