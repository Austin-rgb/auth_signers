use anyhow::Result;
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey, Algorithm};
use std::env;
use std::sync::Arc;
mod signer_core;
use signer_core::{Signer, run_server};
use libsigners::Claims;

struct HS256Signer {
    secret: String,
    header: Header,
    validation: Validation,
}

impl Signer for HS256Signer {
    type Claims = Claims;

    fn sign(&self, claims: &Claims) -> Result<String> {
        Ok(encode(&self.header, claims, &EncodingKey::from_secret(self.secret.as_bytes()))?)
    }

    fn validate(&self, token: &str) -> Result<Claims> {
        let data = decode::<Claims>(token, &DecodingKey::from_secret(self.secret.as_bytes()), &self.validation)?;
        Ok(data.claims)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let tmpdir = env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
    let socket_path = format!("{}/jwt-signer.sock", tmpdir);

    let secret = env::var("SECRET")?;
    let signer = Arc::new(HS256Signer {
        secret,
        header: Header::new(Algorithm::HS256),
        validation: Validation::new(Algorithm::HS256),
    });

    run_server(&socket_path, signer).await
}
