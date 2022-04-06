use crate::error::MultiSigResult;
use serde_derive::{Deserialize, Serialize};
use std::fs;
use toml;

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub encrypted_private_key: Option<String>,
    pub num_signers: usize,
    pub public_keys: Vec<String>,
}

impl Config {
    pub fn from_file(filename: &str) -> MultiSigResult<Self> {
        Ok(toml::from_str(&fs::read_to_string(filename)?)?)
    }

    pub fn to_file(&self, filename: &str) -> MultiSigResult<()> {
        fs::write(filename, toml::to_string_pretty(self)?)?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct State {
    pub secret_list: Vec<String>,
    pub transaction: Option<String>,
    pub partial_signatures: Option<Vec<String>>,
    pub commitment_list: Vec<CommitmentList>,
}


impl State {
    pub fn from_file(filename: &str) -> MultiSigResult<Self> {
        Ok(toml::from_str(&fs::read_to_string(filename)?)?)
    }

    pub fn to_file(&self, filename: &str) -> MultiSigResult<()> {
        fs::write(filename, toml::to_string_pretty(self)?)?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct Commitment {
    pub public_key: String,
    pub commitment: String,
}

#[derive(Serialize, Deserialize)]
pub struct CommitmentList {
    pub public_key: String,
    pub commitment_list: Vec<String>,
}
