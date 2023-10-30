use aes::Aes256;
use beserial::{Deserialize, Serialize};
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use hex;
use hex::FromHex;
use multisig_lib::transaction::{
    aggregate_commitment, aggregate_public_keys, finalize_transaction, SignerCommitments,
    MUSIG2_PARAMETER_V,
};
use nimiq_hash::pbkdf2::compute_pbkdf2_sha512;
use nimiq_keys::multisig::{Commitment, CommitmentPair, PartialSignature, RandomSecret};
use nimiq_keys::{Address, PublicKey};
use nimiq_primitives::networks::NetworkId;
use nimiq_transaction::{Transaction, TransactionFormat};
use nimiq_utils::key_rng::{RngCore, SecureGenerate, SecureRng};
use std::convert::TryFrom;
use std::io;
use std::io::Write;

use curve25519_dalek::scalar::Scalar;

use crate::config::{CommitmentList, State};
use crate::error::{MultiSigError, MultiSigResult};
use crate::multisig::MultiSig;
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
        wallet.address(),
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
    encrypted_secret_list: Vec<String>,
    filename: String,
    process: SigningProcess,
}

impl std::fmt::Display for CliSigningProcess {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "(encrypted_secret_list: {:?}, own_commitment_list: {:?})",
            self.encrypted_secret_list, self.process.own_commitment_pairs
        )
    }
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

        let process = SigningProcess::new(wallet.public_key(), wallet.num_signers, None);

        let mut encrypted_secret_list = vec![];
        for i in 0..MUSIG2_PARAMETER_V {
            let encrypted_secret = encrypt(
                &process.own_commitment_pairs[i].random_secret().0.to_bytes(),
                password.as_ref(),
            )?;
            encrypted_secret_list.push(encrypted_secret);
        }

        println!("❗️ Please give to your co-signers the following information:");
        println!("Public Key: {}", process.own_public_key);

        for (i, c) in process.own_commitment_pairs.iter().enumerate() {
            println!(
                "Commitment {}: {}",
                i + 1,
                hex::encode(c.commitment().to_bytes())
            );
        }

        let mut state = CliSigningProcess {
            encrypted_secret_list,
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
        if self.process.transaction.is_none() {
            self.load_transaction(wallet)?;
        }
        self.print_transaction_details()?;

        if self.process.other_commitment_lists.len() + 1 < self.process.num_signers {
            self.collect_commitments(wallet)?;
        }

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
        while self.process.other_commitment_lists.len() + 1 < self.process.num_signers {
            println!("  Enter a public key:");
            print!(
                "[{}/{}]",
                self.process.other_commitment_lists.len() + 2,
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
                    .other_commitment_lists
                    .iter()
                    .any(|c| c.public_key == pk)
            {
                println!("🤨 Duplicate public key, ignoring this one.");
                continue;
            }
            println!("  Enter the corresponding commitment list:");

            let mut collected_commitment_list = vec![];
            for i in 0..MUSIG2_PARAMETER_V {
                println!("  Enter the {}/{} commitment:", i + 1, MUSIG2_PARAMETER_V);
                let commitment_str = read_line()?;
                let mut commitment = [0u8; Commitment::SIZE];
                let commitment =
                    if let Ok(_) = hex::decode_to_slice(&commitment_str, &mut commitment) {
                        Commitment::from(commitment)
                    } else {
                        println!("🤨 Could not parse the commitment. Try again.");
                        continue;
                    };
                collected_commitment_list.push(commitment);
            }

            self.process.add_other_commitment_list(SignerCommitments {
                public_key: pk,
                commitments: collected_commitment_list,
            })?;

            // Save state.
            self.save()?;
        }

        println!();
        println!(
            "🎉 Step 1 is complete. All signers should now share a common aggregated commitment:"
        );
        let (agg_cm, _b) = self.process.aggregated_commitment()?;
        println!("{}", hex::encode(agg_cm.to_bytes()));
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
        let mut commitment_list: Vec<SignerCommitments> = state
            .commitment_list
            .iter()
            .map(SignerCommitments::try_from)
            .collect::<Result<_, _>>()?;

        // let own_commitment_pair = commitments.pop().ok_or(MultiSigError::MissingCommitments)?;
        let own_commitment_pair_list = commitment_list
            .pop()
            .ok_or(MultiSigError::MissingCommitments)?;

        let mut own_commitment_list = vec![];
        let mut encrypted_secret_list = vec![];

        for i in 0..MUSIG2_PARAMETER_V {
            let random_secret = decrypt(state.secret_list[i].clone(), password)?;
            let mut secret_bytes = [0u8; RandomSecret::SIZE];
            secret_bytes.copy_from_slice(&random_secret);
            let random_secret = RandomSecret::from(secret_bytes);
            let own_commitment =
                CommitmentPair::new(&random_secret, &own_commitment_pair_list.commitments[i]);
            own_commitment_list.push(own_commitment);

            encrypted_secret_list.push(state.secret_list[i].clone());
        }

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
            encrypted_secret_list,
            filename,
            process: SigningProcess {
                num_signers: state.num_signers,
                own_public_key: own_commitment_pair_list.public_key,
                own_commitment_pairs: own_commitment_list,
                other_commitment_lists: commitment_list,
                transaction,
                partial_signatures,
            },
        })
    }
}

pub struct SigningProcess {
    num_signers: usize,
    own_public_key: PublicKey,

    own_commitment_pairs: Vec<CommitmentPair>,
    other_commitment_lists: Vec<SignerCommitments>,

    transaction: Option<Transaction>,
    partial_signatures: Vec<PartialSignature>,
}

impl SigningProcess {
    pub fn new(
        own_public_key: PublicKey,
        num_signers: usize,
        commitment_pairs: Option<Vec<CommitmentPair>>,
    ) -> Self {
        let mut own_commitment_pairs;

        match commitment_pairs {
            Some(pairs) => own_commitment_pairs = pairs,
            None => {
                own_commitment_pairs = vec![];
                for _i in 0..MUSIG2_PARAMETER_V {
                    own_commitment_pairs.push(CommitmentPair::generate_default_csprng());
                }
            }
        }

        Self {
            num_signers,
            own_public_key,
            own_commitment_pairs,
            other_commitment_lists: vec![],
            transaction: None,
            partial_signatures: vec![],
        }
    }

    #[allow(dead_code)]
    pub fn own_commitment_list(&self) -> SignerCommitments {
        SignerCommitments {
            public_key: self.own_public_key,
            commitments: self
                .own_commitment_pairs
                .iter()
                .map(|pair| *pair.commitment())
                .collect(),
        }
    }

    pub fn add_other_commitment_list(
        &mut self,
        commitment_list: SignerCommitments,
    ) -> MultiSigResult<&mut Self> {
        if self.other_commitment_lists.len() >= self.num_signers - 1 {
            return Err(MultiSigError::NoMoreSigners);
        }

        self.other_commitment_lists.push(commitment_list);
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

        let mut public_keys = vec![];
        for c in self.other_commitment_lists.iter() {
            public_keys.push(c.public_key);
        }
        public_keys.push(self.own_public_key);
        public_keys.sort();

        if public_keys.len() != self.num_signers {
            return Err(MultiSigError::MissingCommitments);
        }

        let (aggregated_commitment, b) = self.aggregated_commitment()?;

        let data = self
            .transaction
            .as_ref()
            .ok_or(MultiSigError::MissingTransaction)?
            .serialize_content();

        let partial_signature = wallet.partially_sign(
            &public_keys,
            &aggregated_commitment,
            b.clone(),
            &self.own_commitment_pairs,
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

    // We should calculate delinearized scalars for pre-commitments
    // b = H(aggregated_public_key|(R_1, ..., R_v)|m)
    pub fn aggregated_commitment(&self) -> MultiSigResult<(Commitment, Scalar)> {
        let transaction = self
            .transaction
            .as_ref()
            .ok_or(MultiSigError::MissingTransaction)?;

        Ok(aggregate_commitment(
            &self.other_commitment_lists,
            &self.own_commitment_pairs,
            &self.aggregated_public_key(),
            transaction,
        ))
    }

    pub fn aggregated_public_key(&self) -> PublicKey {
        let mut public_keys: Vec<PublicKey> = self
            .other_commitment_lists
            .iter()
            .map(|scl| scl.public_key)
            .collect();
        public_keys.push(self.own_public_key);

        aggregate_public_keys(&public_keys)
    }

    pub fn sign_transaction(&self, wallet: &MultiSig) -> MultiSigResult<Transaction> {
        if self.partial_signatures.len() != self.num_signers {
            return Err(MultiSigError::MissingSignatures);
        }

        let mut transaction = self
            .transaction
            .as_ref()
            .ok_or(MultiSigError::MissingTransaction)?
            .clone();

        let (aggregated_commitment, _b) = self.aggregated_commitment()?;

        finalize_transaction(
            &mut transaction,
            &self.partial_signatures,
            &aggregated_commitment,
            self.aggregated_public_key(),
            &wallet.public_keys(),
        );

        Ok(transaction)
    }
}

impl<'a> From<&'a CliSigningProcess> for State {
    fn from(c: &'a CliSigningProcess) -> Self {
        let mut commitment_list: Vec<CommitmentList> = c
            .process
            .other_commitment_lists
            .iter()
            .map(CommitmentList::from)
            .collect();
        // Own commitment last.

        let mut own_commitment_list_str = vec![];
        for cm in c.process.own_commitment_pairs.iter() {
            own_commitment_list_str.push(hex::encode(cm.commitment().to_bytes()));
        }
        commitment_list.push(CommitmentList {
            public_key: c.process.own_public_key.to_hex(),
            commitment_list: own_commitment_list_str,
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
            num_signers: c.process.num_signers,
            secret_list: c.encrypted_secret_list.clone(),
            commitment_list,
            transaction: c
                .process
                .transaction
                .as_ref()
                .map(|tx| hex::encode(tx.serialize_to_vec())),
            partial_signatures,
        }
    }
}

impl<'a> From<&'a SignerCommitments> for CommitmentList {
    fn from(c: &'a SignerCommitments) -> Self {
        let mut commitment_list_str = vec![];
        for cm in c.commitments.iter() {
            commitment_list_str.push(hex::encode(cm.to_bytes()));
        }
        CommitmentList {
            public_key: c.public_key.to_hex(),
            commitment_list: commitment_list_str,
        }
    }
}

impl<'a> TryFrom<&'a CommitmentList> for SignerCommitments {
    type Error = MultiSigError;

    fn try_from(c: &'a CommitmentList) -> MultiSigResult<Self> {
        let mut commitment_list_signer = vec![];
        for cm in c.commitment_list.iter() {
            let mut commitment = [0u8; Commitment::SIZE];
            hex::decode_to_slice(&cm, &mut commitment)?;
            commitment_list_signer.push(Commitment::from(commitment));
        }

        Ok(SignerCommitments {
            public_key: PublicKey::from_hex(&c.public_key)?,
            commitments: commitment_list_signer,
        })
    }
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
