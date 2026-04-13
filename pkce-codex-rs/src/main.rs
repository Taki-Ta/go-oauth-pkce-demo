use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use pkce_codex_rs::{
    Client, Config, FileStore, TokenSource, new_pkce, new_state, wait_for_callback,
};

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::from_env();
    let client = Client::new(config.clone());
    let state = new_state();
    let (verifier, challenge) = new_pkce();
    let url = client.authorize_url(&state, &challenge);
    Client::open_browser(&url).await?;
    let result = wait_for_callback(&config.redirect_url).await?;
    if !result.error.is_empty() {
        return Err(anyhow!(
            "oauth callback returned {}: {}",
            result.error,
            result.error_description
        ));
    }
    if result.state != state {
        return Err(anyhow!("oauth callback state mismatch"));
    }

    let token = client.exchange_code(&result.code, &verifier).await?;
    FileStore::new(&config.store_path).save(&token)?;
    let date: DateTime<Utc> =
        DateTime::from_timestamp(token.expires_in, 0).ok_or_else(|| anyhow!("invalid expiry"))?;
    println!("Oauth succeed");
    println!("account id:{}", token.account_id.unwrap_or_default());
    println!("expires at:{}", date.format("%Y-%m-%d %H:%M"));

    let _token_source = TokenSource::new(FileStore::new(&config.store_path), client);
    Ok(())
}
