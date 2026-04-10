mod oauth;
use oauth::config::*;


fn main() {
    let config = Config::from_env();
    println!("config: {:#?}", config);
}
