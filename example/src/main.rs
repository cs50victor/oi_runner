#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::formatted_builder()
        .parse_filters("oi_runner=debug,example=debug")
        .init();
    let oi_runner = oi_runner::get_runner(&reqwest::Client::new(), false).await?;
    log::info!("runner : {oi_runner:?}");

    let venv_path = std::env::current_dir()?.join(".venv");

    oi_runner.create_venv(venv_path.clone(), true)?;

    let pyproject_file_path = std::env::current_dir()?.join("pyproject.toml");

    oi_runner.install_pip_packages(venv_path, pyproject_file_path, true)?;
    log::info!("DONE");
    Ok(())
}
