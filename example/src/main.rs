#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::formatted_builder()
        .parse_filters("oi_runner=debug,example=debug")
        .init();
    let oi_runner = oi_runner::get_runner(&reqwest::Client::new()).await?;
    log::info!("runner : {oi_runner:?}");

    let venv_path = std::env::current_dir()?.join(".venv");

    oi_runner.create_venv(venv_path.clone())?;

    let requirements_file_path = std::env::current_dir()?.join("requirements_example.txt");

    oi_runner.install_pip_packages(venv_path, requirements_file_path)?;
    log::info!("DONE");
    Ok(())
}
