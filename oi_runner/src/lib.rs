use std::{
    cmp::min,
    env::var_os,
    fs::{remove_dir_all, File},
    io::Write as _,
    path::PathBuf,
    process::{Command, Output, Stdio},
};

use anyhow::{anyhow, bail, Context};
use futures_lite::StreamExt as _;
use log::{debug, error, info};
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

pub fn output_to_string(output: &Output) -> anyhow::Result<String> {
    let e = std::str::from_utf8(&output.stderr)?;
    if !e.is_empty() && !output.status.success() {
        debug!("output status {}", output.status);
        error!("{}", e);
        bail!("{}", e)
    }
    Ok(format!(
        "( status {:?} | stderr {} | stdout {}",
        output.status,
        std::str::from_utf8(&output.stdout)?,
        e
    ))
}

pub fn extract_real_output(output: Output) -> anyhow::Result<Output> {
    let e = std::str::from_utf8(&output.stderr)?;
    if !e.is_empty() && !output.status.success() {
        bail!("{e}")
    }
    Ok(output)
}
impl Runner {
    pub fn create_venv(&self, desired_venv_path: PathBuf) -> anyhow::Result<()> {
        info!("venv path : {desired_venv_path:?}");
        if desired_venv_path.exists() {
            remove_dir_all(&desired_venv_path)?;
        }
        let parent_dir = match desired_venv_path.parent() {
            Some(dir) => dir,
            None => bail!("failed to find parent dir to {desired_venv_path:?}"),
        };

        info!(
            "venv parent dir | {parent_dir:?} | exists {}",
            parent_dir.exists()
        );

        let o = match self {
            Runner::PythonAndUv => Command::new("uv")
                .args([
                    "venv",
                    "-p",
                    VALID_PYTHON_VERSION,
                    desired_venv_path.to_string_lossy().as_ref(),
                ])
                .output()
                .context("failed to create venv using uv")?,
            // ensure a "pyproject.toml" file exists in this directory
            Runner::Rye => {
                if !bin_exists("rye")? {
                    info!("rye not found in path, trying to create venv using other methods");
                    // try source \"$HOME/.rye/env
                    if let Some(home_path) = std::env::var_os("HOME") {
                        info!("home path | {home_path:?}");
                        let home = home_path.to_string_lossy().to_string();
                        info!("sourcing rye's env");
                        match extract_real_output(
                            Command::new(SHELL)
                                .args([
                                    "-c",
                                    &format!(
                                        "source {home}/.rye/env && cd {parent_dir:?} && rye sync"
                                    ),
                                ])
                                .output()?,
                        ) {
                            Ok(o) => o,
                            Err(e) => {
                                error!("failed to source rye's env | {e}");
                                info!("using direct link to rye shim");
                                Command::new(SHELL)
                                    .args([
                                        "-c",
                                        &format!("cd {parent_dir:?} && {home}/.rye/shims/rye sync"),
                                    ])
                                    .output()
                                    .context(
                                        "Failed to create venv using direct link to rye shim",
                                    )?
                            }
                        }
                    } else {
                        // TODO: remove later
                        Command::new(SHELL)
                            .args(["-c", &format!("cd {parent_dir:?} && rye sync")])
                            .output()
                            .context("failed to create venv forcefully using rye")?
                    }
                } else {
                    info!("rye found in path, creating venv using rye");
                    Command::new(SHELL)
                        .args(["-c", &format!("cd {parent_dir:?} && rye sync")])
                        .output()
                        .context("failed to create venv using rye")?
                }
            }
        };

        info!(
            "python virtual environment creation result | {}",
            output_to_string(&o)?
        );

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

    pub fn install_pip_packages(
        &self,
        venv_path: PathBuf,
        pyproject_toml_path: PathBuf,
    ) -> anyhow::Result<()> {
        info!("pyproject file_path : {pyproject_toml_path:?}");
        match self {
            // rye sync already handles package installation from pyproject.toml
            Runner::Rye => Ok(()),
            Runner::PythonAndUv => {
                let source_cmd = self.get_source_cmd(venv_path)?;

                #[cfg(unix)]
                let source_and_pip_install_cmd =
                    &format!("source {source_cmd} && uv pip install -r {pyproject_toml_path:?}");

                #[cfg(windows)]
                let source_and_pip_install_cmd =
                    &format!("{source_cmd} && uv pip install -r {pyproject_toml_path:?}");

                #[cfg(unix)]
                let o = Command::new(SHELL)
                    .args(["-c", source_and_pip_install_cmd])
                    .output()?;

                #[cfg(windows)]
                let o = Command::new(source_and_pip_install_cmd).output()?;

                info!(
                    "source and uv pip install output > {}",
                    output_to_string(&o)?
                );
                Ok(())
            }
        }
    }
}

pub fn get_python_bin_name() -> anyhow::Result<String> {
    for potential_name in ["python3.11", "python3", "python", "py"] {
        let o = Command::new(SHELL)
            .args(["-c", &format!("{potential_name} --version")])
            .output()?;
        if std::str::from_utf8(&o.stdout)?
            .trim()
            .to_lowercase()
            .contains(VALID_PYTHON_VERSION)
        {
            let py_bin_name = potential_name.to_owned();
            info!("python bin name | {py_bin_name}");
            return Ok(py_bin_name);
        }
    }
    bail!("no valid python version found");
}
pub async fn get_runner(http_client: &Client) -> anyhow::Result<Runner> {
    if bin_exists("rye")? {
        info!("rye exists, using rye as runner");
        return Ok(Runner::Rye);
    }
    let valid_python_version_exists = get_python_bin_name().is_ok();

    if valid_python_version_exists {
        info!("a valid python version exists");
        let uv_exists = bin_exists("uv")?;
        if uv_exists || download_uv().await.is_ok() {
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

    if bin_exists("gunzip")? && bin_exists("curl")? {
        // use bash to avoid pipefail error
        let o = Command::new(SHELL).args(["-c", "curl -sSf https://rye.astral.sh/get | RYE_TOOLCHAIN_VERSION=\"3.11.9\" RYE_INSTALL_OPTION=\"--yes\" bash"]).output()?;

        info!("rye curl installer resp | {o:#?}");

        if !bin_exists("rye")?
            && !bin_exists(&format!(
                "{:?}/.rye/shims/rye",
                std::env::var_os("HOME").unwrap_or_default()
            ))?
        {
            bail!("{}", std::str::from_utf8(&o.stderr).unwrap());
        }
        return Ok(());
    }

    let rye_file_name = format!("rye-{}-{}", std::env::consts::ARCH, std::env::consts::OS);
    let rye_gz_url =
        &format!("https://github.com/astral-sh/rye/releases/latest/download/{rye_file_name}.gz");
    info!("downloading rye installer {rye_gz_url:?}");
    let rye_gz = download_file(client, rye_gz_url).await?;

    let system_temp_dir = Command::new(SHELL).args(["-c", "echo $TMPDIR"]).output()?;
    let temp_dir = std::env::temp_dir();
    let temp_var_os = var_os("TMPDIR");
    info!("std temp dir {temp_dir:?} | {temp_var_os:?}");
    let system_temp_dir = PathBuf::from(std::str::from_utf8(&system_temp_dir.stdout)?.trim());
    info!("system_temp_dir | {system_temp_dir:?}");
    let rye_installer_path = system_temp_dir.join(".ryeinstaller.oi");
    info!("rye_installer_path | {rye_installer_path:?}");

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

    // rye bin or default rye bin path
    if !bin_exists("rye")?
        && !bin_exists(&format!(
            "{:?}/.rye/shims/rye",
            std::env::var_os("HOME").unwrap_or_default()
        ))?
    {
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

pub async fn download_file<'a>(client: &Client, url: &str) -> anyhow::Result<DownloadResult> {
    let mut downloaded = 0_u64;

    let mut download_resp = DownloadResult::default();

    let res = client
        .get(url)
        .send()
        .await
        .map_err(|e| anyhow!("Failed to GET from '{}': {e}", &url))?;
    let total_size = res
        .content_length()
        .ok_or_else(|| anyhow!("Failed to get content length from '{}'", &url))?;

    if downloaded >= total_size {
        info!("File already completed downloaded.");
        return Ok(download_resp);
    };

    let mut stream = res.bytes_stream();

    // let downloaded_bytes = bytes::BytesMut::new();
    let mut curr_percentage = 0.0_f32;
    while let Some(item) = stream.next().await {
        let chunk = item.map_err(|e| anyhow!("Error while downloading file: {e}"))?;
        download_resp.bytes.extend(&chunk);
        downloaded = min(downloaded + (chunk.len() as u64), total_size);
        let prev_percentage = curr_percentage.round();
        curr_percentage = (downloaded as f32 / total_size as f32) * 100.0;
        if curr_percentage.round() > prev_percentage || prev_percentage == 0.0 {
            info!("downloaded {:.2}%", curr_percentage.round());
        }
    }
    Ok(download_resp)
}

// TODO: add tests
