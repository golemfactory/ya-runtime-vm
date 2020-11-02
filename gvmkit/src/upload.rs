use crate::progress::{Progress, ProgressResult, Spinner, SpinnerResult};
use actix_rt::Arbiter;
use anyhow::Context;
use bytes::Bytes;
use futures::channel::{mpsc, oneshot};
use futures::SinkExt;
use hex::ToHex;
use sha3::Digest;
use std::path::Path;
use std::rc::Rc;
use tokio::io::{AsyncReadExt, BufReader};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

pub(crate) const STEPS: usize = 2;
const PROTOCOL: &'static str = "http";
const DOMAIN: &'static str = "dev.golem.network";

async fn resolve_repo() -> anyhow::Result<String> {
    let resolver: TokioAsyncResolver =
        TokioAsyncResolver::tokio(ResolverConfig::google(), ResolverOpts::default()).await?;

    let lookup = resolver
        .srv_lookup(format!("_girepo._tcp.{}", DOMAIN))
        .await?;
    let srv = lookup
        .iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("Repository SRV record not found at {}", DOMAIN))?;
    let base_url = format!(
        "{}://{}:{}",
        PROTOCOL,
        srv.target().to_string().trim_end_matches('.'),
        srv.port()
    );

    let client = awc::Client::new();
    let response = client
        .get(format!("{}/status", base_url))
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Repository status check failed: {}", e))?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "Repository status check failed with code {}",
            response.status().as_u16()
        ));
    }
    Ok(base_url)
}

pub async fn upload_image<P: AsRef<Path>>(file_path: P) -> anyhow::Result<()> {
    let file_path = file_path.as_ref();
    let progress = Rc::new(Progress::with_eta(
        format!("Uploading '{}'", file_path.display()),
        0,
    ));

    let file = tokio::fs::File::open(&file_path)
        .await
        .with_context(|| format!("Failed to open file: {}", file_path.display()))
        .progress_err(&progress)?;
    let file_name = file_path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("No filename in path: {}", file_path.display()))
        .progress_err(&progress)?
        .to_string_lossy()
        .to_string();
    let file_size = file
        .metadata()
        .await
        .with_context(|| format!("Failed to retrieve file metadata: {}", file_path.display()))
        .progress_err(&progress)?
        .len();

    (*progress).set_total(file_size);

    let repo_url = resolve_repo().await.progress_err(&progress)?;
    log::debug!("Repository URL: {}", repo_url);

    let (mut tx, rx) = mpsc::channel::<Result<Bytes, awc::error::HttpError>>(1);
    let (htx, hrx) = oneshot::channel();

    let progress_ = progress.clone();
    Arbiter::spawn(async move {
        let mut buf = [0; 1024 * 64];
        let mut reader = BufReader::new(file);
        let mut hasher = sha3::Sha3_224::new();

        while let Ok(read) = reader.read(&mut buf[..]).await {
            if read == 0 {
                break;
            }
            if let Err(e) = tx.send(Ok(Bytes::from(buf[..read].to_vec()))).await {
                log::error!("Error uploading image: {}", e);
            }
            hasher.update(&buf[..read]);
            progress_.inc(read as u64);
        }

        if let Err(e) = htx.send(hasher.finalize().encode_hex()) {
            log::error!("Error during hash finalization: {}", e);
        }
    });

    let client = awc::Client::builder().disable_timeout().finish();
    client
        .put(format!("{}/upload/{}", repo_url, file_name))
        .send_stream(rx)
        .await
        .map_err(|e| anyhow::anyhow!("Image upload error: {}", e))
        .progress_result(&progress)?;

    let hash: String = hrx.await?;
    let bytes = format!("{}/{}", repo_url, file_name).as_bytes().to_vec();
    let spinner = Spinner::new(format!("Uploading link for {}", file_name)).ticking();
    client
        .put(format!("{}/upload/image.{}.link", repo_url, hash))
        .send_body(bytes)
        .await
        .map_err(|e| anyhow::anyhow!("Image descriptor upload error: {}", e))
        .spinner_result(&spinner)?;

    println!("{}", hash);
    Ok(())
}
