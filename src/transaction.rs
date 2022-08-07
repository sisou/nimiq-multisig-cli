use aes::Aes256;
use beserial::{Deserialize, Serialize};
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use hex;
use hex::FromHex;
use nimiq_hash::pbkdf2::compute_pbkdf2_sha512;
use nimiq_hash::Blake2bHasher;
use nimiq_keys::multisig::{Commitment, CommitmentPair, PartialSignature, RandomSecret};
use nimiq_keys::{Address, PublicKey};
use nimiq_primitives::networks::NetworkId;
use nimiq_transaction::{SignatureProof, Transaction, TransactionFormat};
use nimiq_utils::key_rng::{RngCore, SecureGenerate, SecureRng};
use nimiq_utils::merkle::Blake2bMerklePath;
use regex::Regex;
use std::convert::TryFrom;
use std::io;
use std::io::Write;

use crate::config::{Commitment as CommitmentState, State};
use crate::error::{MultiSigError, MultiSigResult};
use crate::multisig::MultiSig;
use crate::public_key::DelinearizedPublicKey;
use crate::utils::{read_bool, read_coin, read_line, read_usize};

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

pub fn create_transaction(wallet: &MultiSig) -> MultiSigResult<Transaction> {
    println!("🙈 This step currently only supports basic transactions on the main network.");
    println!("🏷  Please give the recipient address.");
    let recipient_address;
    loop {
        let addr = read_line()?;
        if let Ok(address) = Address::from_any_str(&addr) {
            recipient_address = address;
            break;
        }
        println!("  It looks like this is an invalid address.");
    }

    println!("🤑 How much NIM do you want to send (in NIM)?");
    let value = read_coin()?;

    println!("💸 What is the transaction fee you propose?");
    let fee = read_coin()?;

    println!("⏱ What is the validity start height (when in doubt, take the current block number)?");
    let validity_start_height = read_usize()?;

    let tx = Transaction::new_basic(
        wallet.address()?,
        recipient_address,
        value,
        fee,
        validity_start_height as u32,
        NetworkId::Main,
    );
    println!("👏🏼 Great, here's the transaction:");
    println!("{}", hex::encode(tx.serialize_to_vec()));
    println!();

    Ok(tx)
}

pub struct CliSigningProcess {
    encrypted_secret: String,
    filename: String,
    process: SigningProcess,
}

impl CliSigningProcess {
    pub fn start_signing_process(wallet: &MultiSig) -> MultiSigResult<Self> {
        println!("👏🏼 Let's get started with the signing process.");
        println!("  The process consists of two steps.");
        println!("  1. Collecting all commitments");
        println!("  2. Collecting all signatures");
        println!("  Since this is quite a lot, we'll make sure you can continue the process at any time.");
        println!("🏷  We'll save the current state of the process in a file. How should we name it (the name should end with .toml)?");
        let filename = read_line()?;

        println!("🔑 Since we will store some sensitive data in the file, please give a password to encrypt it with:");
        print!("> ");
        io::stdout().flush()?;
        let password = rpassword::read_password()?;

        println!();
        println!("1️⃣ Step 1a: Creating your own commitment.");
        let process = SigningProcess::new(wallet.public_key(), wallet.num_signers);

        let secret = secret_to_vec(process.own_commitment.random_secret());
        let encrypted_secret = encrypt(&secret, password.as_ref())?;

        println!("❗️ Please give to your co-signers the following information:");
        println!("Public Key: {}", process.own_public_key);
        println!(
            "Commitment: {}",
            hex::encode(process.own_commitment.commitment().to_bytes())
        );

        let mut state = CliSigningProcess {
            encrypted_secret,
            filename,
            process,
        };

        // Save state.
        state.save()?;

        state.continue_signing_process(wallet)?;

        Ok(state)
    }

    pub fn save(&self) -> MultiSigResult<()> {
        State::from(self).to_file(&self.filename)?;
        Ok(())
    }

    pub fn load_signing_process(wallet: &MultiSig) -> MultiSigResult<Self> {
        println!("👏🏼 Let's continue with the signing process.");
        println!("  The process consists of two steps.");
        println!("  1. Collecting all commitments");
        println!("  2. Collecting all signatures");
        println!("🏷  What is the file name of your saved state?");
        let filename = read_line()?;

        println!("🔑 Please enter the encryption password:");
        print!("> ");
        io::stdout().flush()?;
        let password = rpassword::read_password()?;

        let state = State::from_file(&filename)?;
        let mut state = CliSigningProcess::from_state(&state, password.as_ref(), filename)?;

        state.continue_signing_process(wallet)?;

        Ok(state)
    }

    pub fn continue_signing_process(&mut self, wallet: &MultiSig) -> MultiSigResult<()> {
        if self.process.other_commitments.len() + 1 < self.process.num_signers {
            self.collect_commitments(wallet)?;
        }

        if self.process.transaction.is_none() {
            self.load_transaction(wallet)?;
        }
        self.print_transaction_details()?;

        if self.process.partial_signatures.is_empty() {
            println!();
            println!("2️⃣ Step 2a: Creating your own partial signature.");

            let partial_signature = self.process.create_partial_signature(wallet)?;
            self.save()?;

            println!("❗️ Please give to your co-signers the following information:");
            println!(
                "Partial Signature: {}",
                hex::encode(partial_signature.as_bytes())
            );
        }

        if self.process.partial_signatures.len() < self.process.num_signers {
            self.collect_partial_signatures()?;
        }

        println!();
        println!("✅ Finishing transaction.");

        let transaction = self.process.sign_transaction(wallet)?;

        println!("  Here's the fully signed transaction:");
        println!("{}", hex::encode(transaction.serialize_to_vec()));
        println!();

        Ok(())
    }

    pub fn collect_commitments(&mut self, wallet: &MultiSig) -> MultiSigResult<()> {
        println!();
        println!("1️⃣ Step 1b: Collecting the others' commitments.");
        println!("☝🏼 Your intermediate progress will be saved so that you can always return!");
        while self.process.other_commitments.len() + 1 < self.process.num_signers {
            println!("  Enter a public key:");
            print!(
                "[{}/{}]",
                self.process.other_commitments.len() + 2,
                self.process.num_signers
            );
            let pk_str = read_line()?;
            let pk = if let Ok(pk) = PublicKey::from_hex(&pk_str) {
                pk
            } else {
                println!("🤨 This is not a valid public key.");
                continue;
            };

            if self.process.own_public_key != pk && !wallet.public_keys.contains(&pk) {
                println!("🤨 This is not a valid signer of this MultiSig.");
                continue;
            }

            if self.process.own_public_key == pk
                || self
                    .process
                    .other_commitments
                    .iter()
                    .any(|c| c.public_key == pk)
            {
                println!("🤨 Duplicate public key, ignoring this one.");
                continue;
            }

            println!("  Enter the corresponding commitment:");
            let commitment_str = read_line()?;
            let mut commitment = [0u8; Commitment::SIZE];
            let commitment = if let Ok(_) = hex::decode_to_slice(&commitment_str, &mut commitment) {
                Commitment::from(commitment)
            } else {
                println!("🤨 Could not parse the commitment. Try again.");
                continue;
            };

            self.process.add_other_commitment(SignerCommitment {
                public_key: pk,
                commitment,
            })?;

            // Save state.
            self.save()?;
        }

        println!();
        println!(
            "🎉 Step 1 is complete. All signers should now share a common aggregated commitment:"
        );
        println!(
            "{}",
            hex::encode(self.process.aggregated_commitment().to_bytes())
        );
        Ok(())
    }

    pub fn load_transaction(&mut self, wallet: &MultiSig) -> MultiSigResult<Transaction> {
        println!();
        println!("💸 Do you already have a transaction to load? [yes]/no");
        let load_tx = read_bool()?;

        let transaction;
        if load_tx {
            println!("  Just paste the transaction below:");
            loop {
                let tx = read_line()?;
                let tx = if let Ok(tx) = hex::decode(tx) {
                    tx
                } else {
                    println!("🤨 This is not a valid transaction.");
                    continue;
                };

                let tx = if let Ok(tx) = Transaction::deserialize_from_vec(&tx) {
                    tx
                } else {
                    println!("🤨 This is not a valid transaction.");
                    continue;
                };

                transaction = tx;
                break;
            }
        } else {
            println!("  Ok, then let's create a new transaction.");
            transaction = create_transaction(wallet)?;
        }

        self.process.set_transaction(transaction.clone())?;
        self.save()?;

        Ok(transaction)
    }

    pub fn print_transaction_details(&self) -> MultiSigResult<()> {
        let transaction = self
            .process
            .transaction
            .as_ref()
            .ok_or(MultiSigError::MissingTransaction)?;

        println!();
        println!("  Just to make sure. Here are the transaction details:");
        if transaction.format() == TransactionFormat::Extended {
            println!("❗️ This is an extended transaction and the data below is incomplete!");
            println!("❗️ Please check the transaction carefully!");
        }
        println!("Sender: {}", transaction.sender.to_user_friendly_address());
        println!(
            "Recipient: {}",
            transaction.recipient.to_user_friendly_address()
        );
        println!("Value: {} NIM", transaction.value);
        println!("Fee: {} NIM", transaction.fee);

        Ok(())
    }

    pub fn collect_partial_signatures(&mut self) -> MultiSigResult<()> {
        println!();
        println!("2️⃣ Step 2b: Collecting the other signers' partial signatures.");
        while self.process.partial_signatures.len() < self.process.num_signers {
            println!("  Enter a partial signature:");
            print!(
                "[{}/{}]",
                self.process.partial_signatures.len() + 1,
                self.process.num_signers
            );
            let ps_str = read_line()?;
            let mut partial_signature = [0u8; PartialSignature::SIZE];
            let partial_signature =
                if let Ok(_) = hex::decode_to_slice(&ps_str, &mut partial_signature) {
                    PartialSignature::from(partial_signature)
                } else {
                    println!("🤨 This is not a valid partial signature.");
                    continue;
                };

            // if self.partial_signatures.contains(&partial_signature) {
            //     println!("🤨 Duplicate partial signature, ignoring this one.");
            //     continue;
            // }

            self.process.add_partial_signature(partial_signature)?;
            self.save()?;
        }

        println!();
        println!("🎉 Step 2 is complete.");

        Ok(())
    }

    pub fn from_state(state: &State, password: &[u8], filename: String) -> MultiSigResult<Self> {
        let mut commitments: Vec<SignerCommitment> = state
            .commitments
            .iter()
            .map(SignerCommitment::try_from)
            .collect::<Result<_, _>>()?;

        let own_commitment_pair = commitments.pop().ok_or(MultiSigError::MissingCommitments)?;
        let random_secret = decrypt(state.secret.clone(), password)?;
        let mut secret_bytes = [0u8; RandomSecret::SIZE];
        secret_bytes.copy_from_slice(&random_secret);
        let random_secret = RandomSecret::from(secret_bytes);
        let own_commitment = CommitmentPair::new(&random_secret, &own_commitment_pair.commitment);

        let transaction = state
            .transaction
            .as_ref()
            .map(|tx| hex::decode(tx).map(|v| Transaction::deserialize_from_vec(&v)))
            .transpose()?
            .transpose()?;

        let mut partial_signatures: Vec<PartialSignature> = vec![];
        if let Some(ref sigs) = state.partial_signatures {
            for sig in sigs {
                let mut partial_signature = [0u8; PartialSignature::SIZE];
                hex::decode_to_slice(&sig, &mut partial_signature)?;
                partial_signatures.push(PartialSignature::from(partial_signature));
            }
        }

        Ok(CliSigningProcess {
            encrypted_secret: state.secret.clone(),
            filename,
            process: SigningProcess {
                num_signers: state.num_signers,
                own_public_key: own_commitment_pair.public_key,
                own_commitment,
                other_commitments: commitments,
                transaction,
                partial_signatures,
            },
        })
    }
}

pub struct SigningProcess {
    num_signers: usize,
    own_public_key: PublicKey,
    own_commitment: CommitmentPair,
    other_commitments: Vec<SignerCommitment>,
    transaction: Option<Transaction>,
    partial_signatures: Vec<PartialSignature>,
}

pub struct SignerCommitment {
    public_key: PublicKey,
    commitment: Commitment,
}

impl SigningProcess {
    pub fn new(own_public_key: PublicKey, num_signers: usize) -> Self {
        let own_commitment = CommitmentPair::generate_default_csprng();

        Self {
            num_signers,
            own_public_key,
            own_commitment,
            other_commitments: vec![],
            transaction: None,
            partial_signatures: vec![],
        }
    }

    pub fn signer_commitment(&self) -> SignerCommitment {
        SignerCommitment {
            public_key: self.own_public_key,
            commitment: *self.own_commitment.commitment(),
        }
    }

    pub fn add_other_commitment(
        &mut self,
        signer_commitment: SignerCommitment,
    ) -> MultiSigResult<&mut Self> {
        if self.other_commitments.len() >= self.num_signers - 1 {
            return Err(MultiSigError::NoMoreSigners);
        }

        self.other_commitments.push(signer_commitment);
        Ok(self)
    }

    pub fn set_transaction(&mut self, transaction: Transaction) -> MultiSigResult<&mut Self> {
        if self.partial_signatures.len() > 0 {
            return Err(MultiSigError::AlreadySigned);
        }

        self.transaction = Some(transaction);
        Ok(self)
    }

    pub fn create_partial_signature(
        &mut self,
        wallet: &MultiSig,
    ) -> MultiSigResult<PartialSignature> {
        if self.partial_signatures.len() > 0 {
            return Err(MultiSigError::AlreadySigned);
        }

        let data = self
            .transaction
            .as_ref()
            .ok_or(MultiSigError::MissingTransaction)?
            .serialize_content();

        let mut public_keys: Vec<PublicKey> = self
            .other_commitments
            .iter()
            .map(|sc| sc.public_key)
            .collect();
        public_keys.push(self.own_public_key);
        public_keys.sort();

        if public_keys.len() != self.num_signers {
            return Err(MultiSigError::MissingCommitments);
        }

        let mut commitments: Vec<Commitment> = self
            .other_commitments
            .iter()
            .map(|sc| sc.commitment)
            .collect();
        commitments.push(self.signer_commitment().commitment);

        let partial_signature = wallet.partially_sign(
            &public_keys,
            self.own_commitment.random_secret(),
            &commitments,
            &data,
        );

        self.partial_signatures.push(partial_signature);
        Ok(partial_signature)
    }

    pub fn add_partial_signature(
        &mut self,
        partial_signature: PartialSignature,
    ) -> MultiSigResult<&mut Self> {
        if self.partial_signatures.len() == 0 {
            return Err(MultiSigError::MissingOwnSignature);
        }
        if self.partial_signatures.len() >= self.num_signers {
            return Err(MultiSigError::NoMoreSigners);
        }

        self.partial_signatures.push(partial_signature);
        Ok(self)
    }

    pub fn aggregated_commitment(&self) -> Commitment {
        let agg_commitment: Commitment =
            self.other_commitments.iter().map(|sc| &sc.commitment).sum();
        agg_commitment + self.own_commitment.commitment()
    }

    pub fn aggregated_public_key(&self) -> PublicKey {
        let mut public_keys: Vec<PublicKey> = self
            .other_commitments
            .iter()
            .map(|sc| sc.public_key)
            .collect();
        public_keys.push(self.own_public_key);
        public_keys.sort();

        PublicKey::from(DelinearizedPublicKey::sum_delinearized(&public_keys))
    }

    pub fn sign_transaction(&self, wallet: &MultiSig) -> MultiSigResult<Transaction> {
        let aggregated_signature: PartialSignature = self.partial_signatures.iter().sum();
        let signature = aggregated_signature.to_signature(&self.aggregated_commitment());
        let public_key = self.aggregated_public_key();

        let signature_proof = SignatureProof {
            merkle_path: Blake2bMerklePath::new::<Blake2bHasher, _>(
                &wallet.public_keys()?,
                &public_key,
            ),
            public_key,
            signature,
        };

        let mut transaction = self
            .transaction
            .clone()
            .ok_or(MultiSigError::MissingTransaction)?;
        transaction.proof = signature_proof.serialize_to_vec();

        Ok(transaction)
    }
}

impl<'a> From<&'a CliSigningProcess> for State {
    fn from(c: &'a CliSigningProcess) -> Self {
        let mut commitments: Vec<CommitmentState> = c
            .process
            .other_commitments
            .iter()
            .map(CommitmentState::from)
            .collect();
        // Own commitment last.
        commitments.push(CommitmentState {
            public_key: c.process.own_public_key.to_hex(),
            commitment: hex::encode(c.process.own_commitment.commitment().to_bytes()),
        });
        let partial_signatures = if c.process.partial_signatures.is_empty() {
            None
        } else {
            Some(
                c.process
                    .partial_signatures
                    .iter()
                    .map(|ps| hex::encode(ps.as_bytes()))
                    .collect(),
            )
        };
        State {
            secret: c.encrypted_secret.clone(),
            num_signers: c.process.num_signers,
            commitments,
            transaction: c
                .process
                .transaction
                .as_ref()
                .map(|tx| hex::encode(tx.serialize_to_vec())),
            partial_signatures,
        }
    }
}

impl<'a> From<&'a SignerCommitment> for CommitmentState {
    fn from(c: &'a SignerCommitment) -> Self {
        CommitmentState {
            public_key: c.public_key.to_hex(),
            commitment: hex::encode(c.commitment.to_bytes()),
        }
    }
}

impl<'a> TryFrom<&'a CommitmentState> for SignerCommitment {
    type Error = MultiSigError;

    fn try_from(c: &'a CommitmentState) -> MultiSigResult<Self> {
        let mut commitment = [0u8; Commitment::SIZE];
        hex::decode_to_slice(&c.commitment, &mut commitment)?;
        Ok(SignerCommitment {
            public_key: PublicKey::from_hex(&c.public_key)?,
            commitment: Commitment::from(commitment),
        })
    }
}

fn secret_to_vec(secret: &RandomSecret) -> Vec<u8> {
    // This is extremely hacky!
    let s = format!("{:?}", secret);

    let mut v = vec![];
    let re = Regex::new(r"(\d+)").unwrap();
    for cap in re.captures_iter(&s) {
        v.push(cap[0].parse::<u8>().unwrap());
    }
    v
}

const N_ITER: usize = 100_000;
const SALT_LEN: usize = 64;
const KEY_LEN: usize = 32;
const IV_LEN: usize = 16;

fn encrypt(secret: &[u8], password: &[u8]) -> MultiSigResult<String> {
    let mut rng = SecureRng::default();

    let mut salt = [0u8; SALT_LEN];
    rng.fill_bytes(&mut salt);

    let key =
        compute_pbkdf2_sha512(password, &salt, N_ITER, KEY_LEN).or(Err(MultiSigError::Pbkdf2))?;

    let mut iv = [0u8; IV_LEN];
    rng.fill_bytes(&mut iv);

    let cipher = Aes256Cbc::new_from_slices(&key, &iv)?;
    let ciphertext = cipher.encrypt_vec(secret);

    Ok(hex::encode(salt) + &hex::encode(iv) + &hex::encode(ciphertext))
}

fn decrypt(ciphertext: String, password: &[u8]) -> MultiSigResult<Vec<u8>> {
    let ciphertext = hex::decode(ciphertext)?;
    let salt = &ciphertext[0..SALT_LEN];

    let key =
        compute_pbkdf2_sha512(password, salt, N_ITER, KEY_LEN).or(Err(MultiSigError::Pbkdf2))?;

    let iv = &ciphertext[SALT_LEN..SALT_LEN + IV_LEN];

    let cipher = Aes256Cbc::new_from_slices(&key, &iv)?;
    let plaintext = cipher.decrypt_vec(&ciphertext[SALT_LEN + IV_LEN..])?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption() {
        let v = vec![12, 48, 1, 8, 9];
        let pw = vec![2, 5, 11, 54, 128];

        assert_eq!(&decrypt(encrypt(&v, &pw).unwrap(), &pw).unwrap(), &v);
    }
}
