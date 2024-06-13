#[tokio::main]
async fn main() {
    pretty_env_logger::formatted_builder()
        .parse_filters("oi_runner=debug")
        .init();
    let x = oi_runner::get_runner(&reqwest::Client::new()).await;
    println!("runner : {x:?}");
}
