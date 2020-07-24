use anyhow::anyhow;
use std::io::SeekFrom;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt};
use uuid::Uuid;
use ya_runtime_api::deploy::ContainerVolume;

pub async fn get_volumes<Input: AsyncRead + AsyncSeek + Unpin>(
    mut input: Input,
) -> anyhow::Result<Vec<ContainerVolume>> {
    let json_len: u32 = {
        let mut buf = [0; 8];
        input.seek(SeekFrom::End(-8)).await?;
        input.read_exact(&mut buf).await?;
        log::debug!("raw json length: {:?}", buf);
        let buf_str = std::str::from_utf8(&buf)?;
        log::debug!("string json length: {:?}", buf_str);
        buf_str.parse()?
    };
    log::debug!("parsed json length: {:?}", json_len);
    let json: serde_json::Value = {
        let mut buf = String::new();
        input
            .seek(SeekFrom::End(-1 * (json_len + 8) as i64))
            .await?;
        input.take(json_len as u64).read_to_string(&mut buf).await?;
        log::debug!("json: {:?}", buf);
        serde_json::from_str(&buf)?
    };
    let volumes = json
        .get("Volumes")
        .ok_or(anyhow!("Volumes key not found"))?;
    if volumes.is_null() {
        return Ok(Vec::new());
    }
    Ok(volumes
        .as_object()
        .ok_or(anyhow!("Volumes is not an object"))?
        .iter()
        .map(|(key, _value)| ContainerVolume {
            name: format!("vol-{}", Uuid::new_v4()),
            path: key.to_string(),
        })
        .collect())
}
