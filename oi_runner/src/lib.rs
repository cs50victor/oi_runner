use std::{cmp::min, fs::File, io::{Read, Seek as _, Stdin, Write as _}, path::PathBuf, process::{Command, Stdio}};

use anyhow::bail;
use futures_lite::StreamExt as _;
use log::info;
use reqwest::Client;


#[derive(Debug)]
pub enum Runner {
    PythonAndUv,
    Rye
}

const VALID_PYTHON_VERSION : &str = "3.11";

#[cfg(target_os = "macos")]
const SHELL: &str = "zsh";
#[cfg(target_os = "linux")]
const SHELL: &str = "sh";
#[cfg(windows)]
const SHELL: &str = "powershell";

///  check if rye exists
///     if it does, use it as default toolchain
///  else if a valid python version exists
///     if uv
///         use python and uv 
///     download uv
///     use python and uv
///   else download and install rye 
///    return rye as default toolchain
pub async fn get_runner(http_client: &Client) -> anyhow::Result<Runner> {
    if bin_exists("rye")?{
        // return Ok(Runner::Rye);
    }
    let valid_python_version_exists = ["python3.11", "python", "py"].iter().any(|p|{
        let o = std::process::Command::new(SHELL).args(["-c", &format!("{p} --version")]).output().unwrap();
        std::str::from_utf8(&o.stdout).unwrap().trim().to_lowercase().contains(VALID_PYTHON_VERSION)
    });

    if valid_python_version_exists {
        info!("valid python version exists");
        if !bin_exists("uv")? && download_uv().await.is_ok() {
            return Ok(Runner::PythonAndUv);
        };
    }
    // successfully download rye, and check it exists on user's system
    download_rye(http_client).await?;

    Ok(Runner::Rye)
}

fn bin_exists(bin_name: &str) -> anyhow::Result<bool>{
    let o = std::process::Command::new(SHELL).args(["-c", &format!("command -v {bin_name}")]).output()?;

    info!("{bin_name} | {o:?}");

    Ok(!o.stdout.is_empty())
}

async fn download_uv() -> anyhow::Result<()>  {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let o = Command::new(SHELL).args(["-c", "curl -LsSf https://astral.sh/uv/install.sh | sh"]).output()?;
    #[cfg(windows)]
    let o = Command::new(SHELL).args(["-c", "irm https://astral.sh/uv/install.ps1 | iex"]).output()?;
    
    info!("rye curl installer resp | {o:#?}");

    if !bin_exists("uv")? {
        bail!("{}", std::str::from_utf8(&o.stderr)?);
    }

    Ok(())
}

// install rye without downloading additional dependencies
// /usr/bin/gunzip
// /usr/bin/curl
// curl -sSf https://rye.astral.sh/get | RYE_TOOLCHAIN_VERSION="3.11.9" RYE_INSTALL_OPTION="--yes" sh
pub async fn download_rye(client: &Client) -> anyhow::Result<()> {
    if cfg!(not(any(target_arch = "aarch64", target_arch = "x86_64"))) {
        if cfg!(not(any(target_os = "macos", target_os = "linux"))) {
            bail!("Unsupported operating system | Not macos or linux");
        }
        bail!("Unsupported CPU architecture | Not aarch64 or x86_64");
    };
    if !bin_exists("gunzip")? && bin_exists("curl")? {
        let o = Command::new(SHELL).args(["-c", "curl -sSf https://rye.astral.sh/get | RYE_TOOLCHAIN_VERSION=\"3.11.9\" RYE_INSTALL_OPTION=\"--yes\" sh"]).output()?;

        info!("rye curl installer resp | {o:#?}");
        

        if !bin_exists("rye")? {
            bail!("{}", std::str::from_utf8(&o.stderr).unwrap());
        }
        return Ok(());
    }


    let rye_file_name = format!("rye-{}-{}", std::env::consts::ARCH, std::env::consts::OS);
    let rye_gz_url =
        &format!("https://github.com/astral-sh/rye/releases/latest/download/{rye_file_name}.gz");
    info!("downloading rye installer {rye_gz_url:?}");
    let rye_gz = download_file(client, rye_gz_url).await.unwrap();

    let system_temp_dir = Command::new(SHELL).args(["-c", "echo $TMPDIR"]).output()?;
    let system_temp_dir = PathBuf::from(std::str::from_utf8(&system_temp_dir.stdout)?.trim());
    let rye_installer_path = system_temp_dir.join(".ryeinstall.oi");

    // std::fs::set_permissions(rye_installer_path, );

    // remove temp file if exists
    if rye_installer_path.exists() {
        // this bypasses the permission error with remove_file
        std::fs::remove_file(&rye_installer_path)?;
    }

    info!("extracting rye installer bytes {} to  {rye_installer_path:?}", rye_gz.bytes.len());
    // extract to temp file (creating it in the process if it doesn't exist)
    decode_gz_bytes_to_file(rye_gz.bytes.into(), &PathBuf::from(&rye_installer_path))?;

    // chmod installer path (chmod +x ./rye-aarch64-macos)
    info!("giving permission to rye installer binary {rye_installer_path:?}");
    std::process::Command::new(SHELL)
        .args(["-c", &format!("chmod +x {rye_installer_path:?}")])
        .output()?;
    // run rye installer
    info!("running rye installer binary {rye_installer_path:?}");
    let installer = std::process::Command::new(SHELL)
        .stdin(Stdio::null())
        .env("RYE_TOOLCHAIN_VERSION", "3.11.9")
        .args(["-c", &format!("/{rye_installer_path:?} self install --yes")])
        .output()?;

    info!("installer output {installer:?}");

    if !bin_exists("rye")? {
        bail!("{}", std::str::from_utf8(&installer.stderr).unwrap());
    }

    Ok(())
}

/// Uncompresses a Gz Encoded vector
#[allow(unused_assignments)]
fn decode_gz_bytes_to_file(bytes: Vec<u8>, path: &PathBuf) -> anyhow::Result<()> {
    let mut extracted_file = File::create(path)?;
    let mut decoder = flate2::write::GzDecoder::new(extracted_file);
    decoder.write_all(&bytes)?;
    decoder.try_finish()?;
    extracted_file = decoder.finish()?;
    Ok(())
}
// let res = reqwest::get("http://my.api.host/data.json").await;
// info!("{:?}", res.status()); // e.g. 200
// info!("{:?}", res.text().await); // e.g Ok("{ Content }")

#[derive(Default)]
pub struct DownloadResult {
    bytes: bytes::BytesMut,
}

pub async fn download_file<'a>(
    client: &Client,
    url: &str,
) -> Result<DownloadResult, String> {
    // let x = reqwest::Client
    let mut downloaded = 0_u64;

    let mut download_resp = DownloadResult::default();

    let res = client.get(url).send().await.or(Err(format!("Failed to GET from '{}'", &url)))?;
    let total_size =
        res.content_length().ok_or(format!("Failed to get content length from '{}'", &url))?;

    if downloaded >= total_size {
        info!("File already completed downloaded.");
        return Ok(download_resp);
    };

    let mut stream = res.bytes_stream();

    // let downloaded_bytes = bytes::BytesMut::new();
    while let Some(item) = stream.next().await {
        let chunk = item.or(Err("Error while downloading file".to_string()))?;
        download_resp.bytes.extend(&chunk);
        downloaded = min(downloaded + (chunk.len() as u64), total_size);
        info!("downloaded {:.2}%", (downloaded as f64 / total_size as f64) * 100.0);
    }
    Ok(download_resp)
}

// #[cfg(test)]
// mod tests {
    // use super::*;

    // #[test]
    // fn it_works() {
    //     let result = add(2, 2);
    //     assert_eq!(result, 4);
    // }
// }
