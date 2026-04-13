use dotenv::dotenv;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub client: String,
    pub authorize_url: String,
    pub token_url: String,
    pub redirect_url: String,
    pub scopes: Vec<String>,
    pub resource_url: String,
    pub chat_url: String,
    pub chat_model: String,
    pub store_path: String,
}

impl Config {
    pub fn from_env() -> Self {
        dotenv().expect("Failed to load .env file");
        let client = std::env::var("OAUTH_CLIENT_ID").expect("OAUTH_CLIENT_ID must be set");
        let authorize_url =
            std::env::var("OAUTH_AUTHORIZE_URL").expect("OAUTH_AUTHORIZE_URL must be set");
        let token_url = std::env::var("OAUTH_TOKEN_URL").expect("OAUTH_TOKEN_URL must be set");
        let redirect_url =
            std::env::var("OAUTH_REDIRECT_URL").expect("OAUTH_REDIRECT_URL must be set");
        let scopes = std::env::var("OAUTH_SCOPES")
            .expect("OAUTH_SCOPES must be set")
            .split(',')
            .map(ToString::to_string)
            .collect();
        let resource_url =
            std::env::var("OAUTH_RESOURCE_URL").expect("OAUTH_RESOURCE_URL must be set");
        let chat_url = std::env::var("OAUTH_CHAT_URL").expect("OAUTH_CHAT_URL must be set");
        let chat_model = std::env::var("OAUTH_CHAT_MODEL").expect("OAUTH_CHAT_MODEL must be set");
        let store_path =
            std::env::var("OAUTH_STORE_PATH").unwrap_or_else(|_| "store.json".to_string());
        Config {
            client,
            authorize_url,
            token_url,
            redirect_url,
            scopes,
            resource_url,
            chat_url,
            chat_model,
            store_path,
        }
    }
}
