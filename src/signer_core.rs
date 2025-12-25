use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use anyhow::Result;
use serde::{Serialize, de::DeserializeOwned};
use std::sync::Arc;

pub trait Signer: Send + Sync + 'static {
    type Claims: Serialize + DeserializeOwned + Send + Sync;

    fn sign(&self, claims: &Self::Claims) -> Result<String>;
    fn validate(&self, token: &str) -> Result<Self::Claims>;
}

pub async fn run_server<S: Signer>(
    socket_path: &str,
    signer: Arc<S>,
) -> Result<()> {
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)?;
    println!("Signer listening on {}", socket_path);

    loop {
        let (stream, _) = listener.accept().await?;
        let signer = signer.clone();

        tokio::spawn(async move {
            let (r, mut w) = stream.into_split();
            let mut reader = BufReader::new(r);
            let mut line = String::new();

            while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    line.clear();
                    continue;
                }

                let req: serde_json::Value = match serde_json::from_str(trimmed) {
                    Ok(v) => v,
                    Err(_) => {
                        let _ = w.write_all(b"ERROR Invalid JSON\n").await;
                        line.clear();
                        continue;
                    }
                };

                match req["cmd"].as_str() {
                    Some("sign") => {
                        match serde_json::from_value(req["claims"].clone()) {
                            Ok(claims) => match signer.sign(&claims) {
                                Ok(token) => {
                                    let _ = w.write_all(format!("TOKEN {}\n", token).as_bytes()).await;
                                }
                                Err(e) => {
                                    let _ = w.write_all(format!("ERROR {}\n", e).as_bytes()).await;
                                }
                            },
                            Err(_) => {
                                let _ = w.write_all(b"ERROR Invalid claims\n").await;
                            }
                        }
                    }

                    Some("validate") => {
                        let token = req["token"].as_str().unwrap_or("");
                        match signer.validate(token) {
                            Ok(claims) => {
                                let json = serde_json::to_string(&claims).unwrap();
                                let _ = w.write_all(format!("VALID {}\n", json).as_bytes()).await;
                            }
                            Err(e) => {
                                let _ = w.write_all(format!("ERROR {}\n", e).as_bytes()).await;
                            }
                        }
                    }

                    _ => {
                        let _ = w.write_all(b"ERROR Unknown command\n").await;
                    }
                }

                line.clear();
            }
        });
    }
}
