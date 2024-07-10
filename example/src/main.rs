#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::formatted_builder()
        .parse_filters("oi_runner=debug,example=debug")
        .init();

    let cli_args = std::env::args().collect::<Vec<String>>();
    log::info!("cli args : {cli_args:?}");

    // this is lazy, but it works, in a rush
    let use_path_name_with_spaces = match cli_args.get(1).map(|arg| arg.as_str()).unwrap_or("false")
    {
        "true" => true,
        "false" => false,
        _ => false,
    };

    log::info!("use_path_name_with_spaces : {use_path_name_with_spaces}");

    let mut base_path = std::env::current_dir()?;

    if use_path_name_with_spaces {
        base_path = base_path.join("dir with spaces");
        std::fs::create_dir_all(&base_path)?;
    }

    let oi_runner = oi_runner::get_runner(&reqwest::Client::new(), false).await?;
    log::info!("runner : {oi_runner:?}");

    let venv_path = base_path.join(".venv");

    log::info!("venv_path : {venv_path:?}");

    oi_runner.create_venv(venv_path.clone(), true)?;

    let pyproject_file_path = base_path.join("pyproject.toml");

    log::info!("pyproject file path : {}", pyproject_file_path.display());

    oi_runner.install_pip_packages(venv_path, pyproject_file_path, true)?;
    log::info!("DONE");
    Ok(())
}
