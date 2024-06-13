use std::{
    cmp::min,
    fs::{remove_dir_all, File},
    io::Write as _,
    path::PathBuf,
    process::{Command, Output, Stdio},
};

use anyhow::bail;
use futures_lite::StreamExt as _;
use log::info;
use reqwest::Client;

const VALID_PYTHON_VERSION: &str = "3.11";

#[cfg(target_os = "macos")]
const SHELL: &str = "zsh";
#[cfg(target_os = "linux")]
const SHELL: &str = "sh";
#[cfg(windows)]
const SHELL: &str = "powershell";



#[derive(Debug)]
pub enum Runner {
    PythonAndUv,
    Rye,
}

pub fn output_to_string(output: &Output) -> anyhow::Result<String>{
    Ok(format!(
        "( status {:?} | stderr {} | stdout {}",
        output.status,
        std::str::from_utf8(&output.stderr)?,
        std::str::from_utf8(&output.stdout)?
    ))
}
impl Runner {
    pub fn create_venv(&self, desired_venv_path: PathBuf) -> anyhow::Result<()> {
        if desired_venv_path.exists() {
            remove_dir_all(&desired_venv_path)?;
        }
        let parent_dir = match desired_venv_path.parent(){
            Some(dir) => dir,
            None => bail!("failed to find parent dir to {desired_venv_path:?}"),
        };
        let o = match self {
            Runner::PythonAndUv => Command::new("uv").args(["venv", "-p", VALID_PYTHON_VERSION, (desired_venv_path.to_str().unwrap())]).output()?,
            // ensure a "pyproject.toml" file exists in this directory
            Runner::Rye => Command::new(SHELL).args(["-c", &format!("cd {parent_dir:?} && rye sync")]).output()?,
        };

        info!("python virtual environment creation result | {}", output_to_string(&o)?);

        if !desired_venv_path.exists() {
            bail!("venv creation script ran but venv_path wasn't created. weird");
        }
        Ok(())
    }

    pub fn get_source_cmd(&self, venv_path: PathBuf) -> anyhow::Result<String> {
        #[cfg(windows)]
        let venv_path_str = venv_path.join("Scripts\\activate");
        #[cfg(unix)]
        let venv_path_str = venv_path.join("bin/activate");

        match venv_path_str.to_str() {
            Some(p) => Ok(p.to_owned()),
            None => bail!("couldn't create venv path"),
        }
    }
    
    pub fn install_pip_packages(&self, venv_path: PathBuf, requirements_file_path: PathBuf) -> anyhow::Result<()>{
        match self {
            // rye sync already handles package installation from pyproject.toml
            Runner::Rye => Ok(()),
            Runner::PythonAndUv => {
                let source_cmd = self.get_source_cmd(venv_path)?;

                #[cfg(unix)]
                let source_and_pip_install_cmd =
                    &format!("source {source_cmd} && uv pip install -r {requirements_file_path:?}");
                
                #[cfg(windows)]
                let source_and_pip_install_cmd =
                    &format!("{source_cmd} && uv pip install -r {requirements_file_path:?}");

                #[cfg(unix)]
                let o = Command::new(SHELL).args(["-c", source_and_pip_install_cmd]).output()?;
                
                #[cfg(windows)]
                let o = Command::new(source_and_pip_install_cmd).output()?;
                
                info!("source and uv pip install output > {}",output_to_string(&o)?);
                Ok(())
            },
        }
    }
}

pub async fn get_runner(http_client: &Client) -> anyhow::Result<Runner> {
    if bin_exists("rye")? {
        info!("rye exists, using rye as runner");
        return Ok(Runner::Rye);
    }
    let valid_python_version_exists = ["python3.11", "python3" , "python", "py"].iter().any(|p| {
        let o = Command::new(SHELL)
            .args(["-c", &format!("{p} --version")])
            .output()
            .unwrap();
        std::str::from_utf8(&o.stdout)
            .unwrap()
            .trim()
            .to_lowercase()
            .contains(VALID_PYTHON_VERSION)
    });

    if valid_python_version_exists {
        info!("a valid python version exists");
        let uv_exists = bin_exists("uv")?;
        if uv_exists || download_uv().await.is_ok(){
            return Ok(Runner::PythonAndUv);
        }
    }
    info!("a valid python version wasn't found or a valid python version was found but 'uv' wasn't found ");
    
    info!("installing rye");
    // successfully download rye, and check it exists on user's system
    download_rye(http_client).await?;

    Ok(Runner::Rye)
}

fn bin_exists(bin_name: &str) -> anyhow::Result<bool> {
    let o = Command::new(SHELL)
        .args(["-c", &format!("command -v {bin_name}")])
        .output()?;

    info!("{bin_name} | {o:?}");

    Ok(!o.stdout.is_empty())
}

async fn download_uv() -> anyhow::Result<()> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let o = Command::new(SHELL)
        .args(["-c", "curl -LsSf https://astral.sh/uv/install.sh | sh"])
        .output()?;
    #[cfg(windows)]
    let o = Command::new(SHELL)
        .args(["-c", "irm https://astral.sh/uv/install.ps1 | iex"])
        .output()?;

    info!("rye curl installer resp | {o:#?}");

    if !bin_exists("uv")? {
        bail!("{}", std::str::from_utf8(&o.stderr)?);
    }

    Ok(())
}

// install rye without downloading additional dependencies
// /usr/bin/gunzip
// /usr/bin/curl
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

    info!(
        "extracting rye installer bytes {} to  {rye_installer_path:?}",
        rye_gz.bytes.len()
    );
    // extract to temp file (creating it in the process if it doesn't exist)
    decode_gz_bytes_to_file(rye_gz.bytes.into(), &PathBuf::from(&rye_installer_path))?;

    // chmod installer path (chmod +x ./rye-aarch64-macos)
    info!("giving permission to rye installer binary {rye_installer_path:?}");
    Command::new(SHELL)
        .args(["-c", &format!("chmod +x {rye_installer_path:?}")])
        .output()?;
    // run rye installer
    info!("running rye installer binary {rye_installer_path:?}");
    let installer = Command::new(SHELL)
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

/// Uncompress a Gz Encoded vector
#[allow(unused_assignments)]
fn decode_gz_bytes_to_file(bytes: Vec<u8>, path: &PathBuf) -> anyhow::Result<()> {
    let mut extracted_file = File::create(path)?;
    let mut decoder = flate2::write::GzDecoder::new(extracted_file);
    decoder.write_all(&bytes)?;
    decoder.try_finish()?;
    extracted_file = decoder.finish()?;
    Ok(())
}

#[derive(Default)]
pub struct DownloadResult {
    bytes: bytes::BytesMut,
}

pub async fn download_file<'a>(client: &Client, url: &str) -> Result<DownloadResult, String> {
    let mut downloaded = 0_u64;

    let mut download_resp = DownloadResult::default();

    let res = client
        .get(url)
        .send()
        .await
        .or(Err(format!("Failed to GET from '{}'", &url)))?;
    let total_size = res
        .content_length()
        .ok_or(format!("Failed to get content length from '{}'", &url))?;

    if downloaded >= total_size {
        info!("File already completed downloaded.");
        return Ok(download_resp);
    };

    let mut stream = res.bytes_stream();

    // let downloaded_bytes = bytes::BytesMut::new();
    let mut curr_percentage = 0.0;
    while let Some(item) = stream.next().await {
        let chunk = item.or(Err("Error while downloading file".to_string()))?;
        download_resp.bytes.extend(&chunk);
        downloaded = min(downloaded + (chunk.len() as u64), total_size);
        curr_percentage = (downloaded as f64 / total_size as f64) * 100.0;
        if curr_percentage % 10.0 == 0.0 || curr_percentage % 5.0 == 0.0 {
            info!(
                "downloaded {:.2}%",
                curr_percentage
            );

        }
    }
    Ok(download_resp)
}

// TODO: add tests