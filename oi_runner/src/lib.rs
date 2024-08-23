use std::{
    cmp::min,
    env::var_os,
    fs::{remove_dir_all, File},
    io::Write as _,
    path::PathBuf,
    process::{Command, Output, Stdio},
    vec,
};

use anyhow::{anyhow, bail, Context};
use futures_lite::StreamExt as _;
use log::{debug, error, info};
use reqwest::Client;

const VALID_PYTHON_VERSION: &str = "3.11.9";

#[cfg(target_os = "macos")]
const SHELL: &str = "zsh";
// #[cfg(unix)]
#[cfg(target_os = "linux")]
const SHELL: &str = "sh";
#[cfg(windows)]
const SHELL: &str = "powershell";

#[derive(Debug)]
pub enum Runner {
    Uv,
    Rye,
}

pub fn output_to_string(output: &Output) -> anyhow::Result<String> {
    let e = String::from_utf8_lossy(&output.stderr);
    if !e.is_empty() && !output.status.success() {
        debug!("output status {}", output.status);
        error!("{}", e);
        bail!("{}", e)
    }
    Ok(format!(
        "( status {:?} | stderr {} | stdout {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        e
    ))
}

pub fn extract_real_output(output: Output) -> anyhow::Result<Output> {
    let e = String::from_utf8_lossy(&output.stderr);
    if !e.is_empty() && !output.status.success() {
        bail!("{e}")
    }
    Ok(output)
}

impl Runner {
    pub fn get_bin_path(&self, custom_dir_name: Option<&str>) -> anyhow::Result<String> {
        let home_dir_path = dir_name_to_home_dir(custom_dir_name)?;
        let bin_path = match self {
            Runner::Uv => dir_to_uv_bin(home_dir_path),
            Runner::Rye => dir_to_rye_bin(home_dir_path),
        };
        if !PathBuf::from(&bin_path).exists() {
            let bin_alias = match self {
                Runner::Uv => "uv",
                Runner::Rye => "rye",
            };
            let (exists, path) = bin_exists(bin_alias)?;
            if !exists {
                bail!("binary with name / alias {bin_alias} not found");
            }
            return Ok(path);
        }
        Ok(bin_path)
    }
    pub fn create_venv(
        &self,
        desired_venv_path: PathBuf,
        increase_ulimit: bool,
        custom_runner_dir_name: Option<&str>,
    ) -> anyhow::Result<()> {
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

        let parent_dir = format!("'{}'", parent_dir.to_string_lossy());

        info!("parent dir | {parent_dir}");

        let ulimit_cmd = if increase_ulimit {
            "ulimit -n 4096 && "
        } else {
            ""
        };

        let runner_bin_path = self.get_bin_path(custom_runner_dir_name)?;
        let o = match self {
            // uv creates a venv for us during run `uv run ....`
            Runner::Uv => {
                info!("uv bin path | {runner_bin_path} | custom_rye_dir_name | {custom_runner_dir_name:?}");

                Command::new(SHELL)
                    .args([
                        "-c",
                        &format!("cd {parent_dir} && {runner_bin_path} venv && {ulimit_cmd} {runner_bin_path} pip install -r pyproject.toml"),
                    ])
                    .output()
                    .context("failed to create venv forcefully using rye")?
            }
            // ensure a "pyproject.toml" file exists in this directory
            Runner::Rye => {
                info!("rye bin path | {runner_bin_path} | custom_rye_dir_name | {custom_runner_dir_name:?}");

                Command::new(SHELL)
                    .args([
                        "-c",
                        &format!("cd {parent_dir} && {ulimit_cmd} {runner_bin_path} sync"),
                    ])
                    .output()
                    .context("failed to create venv forcefully using rye")?
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

    pub fn get_source_cmd(&self, venv_path: PathBuf) -> String {
        #[cfg(windows)]
        let venv_path_str = venv_path.join("Scripts\\activate");
        #[cfg(unix)]
        let venv_path_str = venv_path.join("bin/activate");

        format!("'{}'", venv_path_str.to_string_lossy())
    }
}

pub fn get_python_bin_name(custom_rye_dir_name: Option<&str>) -> anyhow::Result<String> {
    let py_dirs = vec![
        format!(
            "{}/.rye/self/bin/python",
            dir_name_to_home_dir(custom_rye_dir_name)?
        ),
        "python3.11".into(),
        "python3".into(),
        "python".into(),
        "py".into(),
    ];

    for potential_name in py_dirs {
        let o = Command::new(SHELL)
            .args(["-c", &format!("{potential_name} --version")])
            .output()?;

        if String::from_utf8_lossy(&o.stdout)
            .trim()
            .to_lowercase()
            .contains(VALID_PYTHON_VERSION)
            || String::from_utf8_lossy(&o.stderr)
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

pub async fn get_runner(
    http_client: &Client,
    custom_runner_dir_name: Option<&str>,
) -> anyhow::Result<Runner> {
    // TODO: add support for uv runners without a custom dir
    let using_custom_dir = custom_runner_dir_name.is_some();
    let uv_bin_name = if using_custom_dir {
        dir_to_uv_bin(dir_name_to_home_dir(custom_runner_dir_name)?)
    } else {
        "uv".to_string()
    };

    if bin_exists(&uv_bin_name)?.0 && using_custom_dir {
        info!("uv exists, using uv as runner");
        return Ok(Runner::Uv);
    };

    if using_custom_dir {
        match download_uv(custom_runner_dir_name).await {
            Ok(_) => return Ok(Runner::Uv),
            Err(e) => {
                info!("failed to download uv, falling back to rye, error: {e:?}");
            }
        }
    }

    let rye_bin_name = if using_custom_dir {
        dir_to_rye_bin(dir_name_to_home_dir(custom_runner_dir_name)?)
    } else {
        "rye".to_string()
    };

    if bin_exists(&rye_bin_name)?.0 {
        info!("rye exists, using rye as runner");
        return Ok(Runner::Rye);
    };

    info!("rye not found, installing rye");
    // successfully download rye, and check it exists on user's system
    download_rye(http_client, custom_runner_dir_name).await?;

    Ok(Runner::Rye)
}

fn bin_exists(bin_name: &str) -> anyhow::Result<(bool, String)> {
    let o = Command::new(SHELL)
        .args(["-c", &format!("command -v {bin_name}")])
        .output()?;

    info!("{bin_name} | {o:?}");

    Ok((
        !o.stdout.is_empty(),
        String::from_utf8_lossy(&o.stdout).trim().to_string(),
    ))
}

async fn download_uv(dir: Option<&str>) -> anyhow::Result<()> {
    let uv_home = dir_name_to_home_dir(dir)?;

    info!("uv home dir  | {uv_home}");

    #[cfg(unix)]
    let install_script = if bin_exists("curl")?.0 {
        format!("curl -LsSf https://astral.sh/uv/install.sh | CARGO_DIST_FORCE_INSTALL_DIR={uv_home} sh")
    } else {
        bail!("curl is not installed. Unable to download uv.");
    };

    #[cfg(windows)]
    let install_script = format!(
        "iwr https://astral.sh/uv/install.ps1 -useb | CARGO_DIST_FORCE_INSTALL_DIR={uv_home} iex"
    );

    println!("install_script, {install_script}");
    let o = Command::new(SHELL)
        .env("CARGO_DIST_FORCE_INSTALL_DIR", uv_home.clone())
        .args(["-c", &install_script])
        .output()
        .context("Failed to install uv in custom location")?;

    let uv_bin_path = dir_to_uv_bin(uv_home);

    info!("uv_bin_path, {uv_bin_path:?}");
    if !PathBuf::from(uv_bin_path.clone()).exists() {
        error!("uv curl output {:#?}", output_to_string(&o));
        bail!("uv installation script ran but uv wasn't found in the expected location");
    }

    let bin_alias = if dir.is_none() {
        "uv".to_owned()
    } else {
        uv_bin_path
    };

    // download python using uv using `uv python install 3.11.8`
    let output = Command::new(bin_alias)
        .args(["python", "install", VALID_PYTHON_VERSION])
        .output()
        .context("Failed to install Python using uv")?;

    info!("uv python install output {:#?}", output_to_string(&output));

    if !output.status.success() {
        bail!(
            "Failed to install Python {}: {}",
            VALID_PYTHON_VERSION,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    info!(
        "Successfully installed Python {} using uv",
        VALID_PYTHON_VERSION
    );

    Ok(())
}

pub fn parse_uv_version_output(version_info: &str) -> anyhow::Result<(u16, u16, u16)> {
    // Remove "uv" and split by opening bracket
    let version_str = version_info
        .trim_start_matches("uv")
        .split('(')
        .next()
        .ok_or_else(|| anyhow!("Invalid version format"))?
        .trim();

    // Parse the version number
    let numbers = version_str.split('.').collect::<Vec<_>>();
    if numbers.len() != 3 {
        bail!("Invalid version format, expected 3 numbers separated by dots");
    }
    let numbers = numbers
        .iter()
        .map(|s| s.parse::<u16>())
        .collect::<Result<Vec<_>, _>>()?;
    Ok((numbers[0], numbers[1], numbers[2]))
}

pub fn dir_to_uv_bin(path: String) -> String {
    format!("{:?}/bin/uv", path).replace("\"", "")
}

// install rye without downloading additional dependencies
// /usr/bin/gunzip
// /usr/bin/curl
pub async fn download_rye(
    client: &Client,
    custom_rye_dir_name: Option<&str>,
) -> anyhow::Result<()> {
    if cfg!(not(any(target_arch = "aarch64", target_arch = "x86_64"))) {
        if cfg!(not(any(target_os = "macos", target_os = "linux"))) {
            bail!("Unsupported operating system | Not macos or linux");
        }
        bail!("Unsupported CPU architecture | Not aarch64 or x86_64");
    };

    let home_dir = dir_name_to_home_dir(custom_rye_dir_name)?;
    let rye_home = format!("{}/.rye", home_dir);

    if bin_exists("gunzip")?.0 && bin_exists("curl")?.0 {
        // use bash to avoid pipefail error
        let o = Command::new(SHELL)
        .env("RYE_HOME", rye_home.clone())
        .args(["-c", &format!("curl -sSf https://rye.astral.sh/get | RYE_TOOLCHAIN_VERSION={VALID_PYTHON_VERSION} RYE_INSTALL_OPTION=\"--yes\" bash")]).output()?;

        info!("rye curl installer resp | {o:#?}");

        // dir_name_to_home_dir(home_dir)
        // dir_to_rye_bin(home_dir)
        if !bin_exists("rye")?.0 && !bin_exists(&dir_to_rye_bin(home_dir))?.0 {
            bail!("{}", String::from_utf8_lossy(&o.stderr));
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
    let system_temp_dir = PathBuf::from(String::from_utf8_lossy(&system_temp_dir.stdout).trim());
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
        .env("RYE_TOOLCHAIN_VERSION", VALID_PYTHON_VERSION)
        .env("RYE_HOME", rye_home)
        .args(["-c", &format!("/{rye_installer_path:?} self install --yes")])
        .output()?;

    info!("installer output {installer:?}");

    // rye bin or default rye bin path
    if !bin_exists("rye")?.0 && !bin_exists(&dir_to_rye_bin(home_dir))?.0 {
        bail!("{}", String::from_utf8_lossy(&installer.stderr));
    }

    Ok(())
}

pub fn dir_name_to_home_dir(custom_runner_dir: Option<&str>) -> anyhow::Result<String> {
    let home = match std::env::var_os("HOME") {
        Some(h) => h,
        None => bail!("HOME env var not found"),
    };
    let mut base_home = PathBuf::from(home);

    if custom_runner_dir.is_some() {
        base_home = base_home.join(custom_runner_dir.unwrap());
    };

    Ok(base_home.to_string_lossy().to_string())
}

pub fn dir_to_rye_bin(path: String) -> String {
    format!("{:?}/.rye/shims/rye", path).replace("\"", "")
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    use tempfile::TempDir;

    #[test]
    fn test_output_to_string() {
        let output = Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: b"Hello".to_vec(),
            stderr: b"".to_vec(),
        };
        let result = output_to_string(&output).unwrap();
        assert!(result.contains("Hello"));

        let output_with_error = Output {
            status: std::process::ExitStatus::from_raw(1),
            stdout: b"".to_vec(),
            stderr: b"Error".to_vec(),
        };
        assert!(output_to_string(&output_with_error).is_err());
    }

    #[test]
    fn test_extract_real_output() {
        let output = Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: b"Success".to_vec(),
            stderr: b"".to_vec(),
        };
        let result = extract_real_output(output).unwrap();
        assert_eq!(result.stdout, b"Success");

        let output_with_error = Output {
            status: std::process::ExitStatus::from_raw(1),
            stdout: b"".to_vec(),
            stderr: b"Error".to_vec(),
        };
        assert!(extract_real_output(output_with_error).is_err());
    }

    #[test]
    fn test_dir_name_to_home_dir() {
        std::env::set_var("HOME", "/home/user");

        let result = dir_name_to_home_dir(None).unwrap();
        assert_eq!(result, "/home/user");

        let result = dir_name_to_home_dir(Some("custom")).unwrap();
        assert_eq!(result, "/home/user/custom");
    }

    #[test]
    fn test_dir_to_rye_bin() {
        let result = dir_to_rye_bin("/home/user".to_string());
        assert_eq!(result, "/home/user/.rye/shims/rye");
    }

    #[test]
    fn test_dir_to_uv_bin() {
        let result = dir_to_uv_bin("/home/user/.custom".to_string());
        assert_eq!(result, "/home/user/.custom/bin/uv");
    }

    #[test]
    fn test_decode_gz_bytes_to_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");

        // Create a simple gzipped content
        let content = b"Hello, World!";
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(content).unwrap();
        let compressed = encoder.finish().unwrap();

        decode_gz_bytes_to_file(compressed, &file_path).unwrap();

        assert!(file_path.exists());
        let file_content = std::fs::read_to_string(file_path).unwrap();
        assert_eq!(file_content, "Hello, World!");
    }

    #[test]
    fn test_bin_exists() {
        // This test assumes that 'ls' exists on the system
        assert!(bin_exists("ls").unwrap().0);
        assert!(!bin_exists("non_existent_binary").unwrap().0);
    }
    // uv version number tests

    #[test]
    fn test_parse_curl_installation_version() {
        let version_info = "uv 0.3.1 (be17d132a 2024-08-21)";
        assert_eq!(parse_uv_version_output(version_info).unwrap(), (0, 3, 1));
    }

    #[test]
    fn test_parse_homebrew_installation_version() {
        let version_info = "uv 0.3.0 (Homebrew 2024-08-20)";
        assert_eq!(parse_uv_version_output(version_info).unwrap(), (0, 3, 0));
    }

    #[test]
    fn test_parse_future_version() {
        let version_info = "uv 1.2.3 (future release)";
        assert_eq!(parse_uv_version_output(version_info).unwrap(), (1, 2, 3));
    }

    #[test]
    fn test_invalid_format_no_uv_prefix() {
        let version_info = "0.3.1 (no prefix)";
        assert_eq!(parse_uv_version_output(version_info).unwrap(), (0, 3, 1));
    }

    #[test]
    fn test_empty_string() {
        let version_info = "";
        assert!(parse_uv_version_output(version_info).is_err());
    }
}
