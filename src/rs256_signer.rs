use anyhow::Result;
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey, Algorithm};
use std::env;
use std::sync::Arc;
use libsigners::Claims;
mod signer_core;
use signer_core::{Signer, run_server};

struct RS256Signer {
    enc_key: EncodingKey,
    dec_key: DecodingKey,
    header: Header,
    validation: Validation,
}

impl Signer for RS256Signer {
    type Claims = Claims;

    fn sign(&self, claims: &Claims) -> Result<String> {
        Ok(encode(&self.header, claims, &self.enc_key)?)
    }

    fn validate(&self, token: &str) -> Result<Claims> {
        let data = decode::<Claims>(token, &self.dec_key, &self.validation)?;
        Ok(data.claims)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let tmpdir = env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
    let socket_path = format!("{}/jwt-signer.sock", tmpdir);

    let private_key = env::var("RSA_PRIVATE_KEY")?;
    let public_key = env::var("RSA_PUBLIC_KEY")?;
    let enc_key = EncodingKey::from_rsa_pem(private_key.as_bytes())?;
    let dec_key = DecodingKey::from_rsa_pem(public_key.as_bytes())?;

    let signer = Arc::new(RS256Signer {
        enc_key,
        dec_key,
        header: Header::new(Algorithm::RS256),
        validation: Validation::new(Algorithm::RS256),
    });

    run_server(&socket_path, signer).await
}
