use crate::oauth::{client::Client, store::FileStore};
use anyhow::{Result, anyhow};

#[derive(Debug, Clone)]
pub struct TokenSource {
    store: FileStore,
    client: Client,
    refresh_skew_secs: i64,
}

impl TokenSource {
    pub fn new(store: FileStore, client: Client) -> Self {
        Self {
            store,
            client,
            refresh_skew_secs: 120,
        }
    }

    pub fn with_refresh_skew_secs(mut self, refresh_skew_secs: i64) -> Self {
        self.refresh_skew_secs = refresh_skew_secs;
        self
    }

    pub async fn valid_token(&self) -> Result<crate::oauth::client::TokenSet> {
        let token = self.store.load()?;
        let now = chrono::Utc::now().timestamp();
        if token.expires_in - now > self.refresh_skew_secs {
            return Ok(token);
        }
        if token.refresh_token.is_empty() {
            return Err(anyhow!(
                "access token is expiring and no refresh token is stored; run login again"
            ));
        }

        let mut refreshed = self.client.refresh(&token.refresh_token).await?;
        if refreshed.refresh_token.is_empty() {
            refreshed.refresh_token = token.refresh_token;
        }
        if refreshed.account_id.is_none() {
            refreshed.account_id = token.account_id;
        }
        self.store.save(&refreshed)?;
        Ok(refreshed)
    }

    pub async fn force_refresh(&self) -> Result<crate::oauth::client::TokenSet> {
        let token = self.store.load()?;
        if token.refresh_token.is_empty() {
            return Err(anyhow!("no refresh token stored; run login again"));
        }

        let mut refreshed = self.client.refresh(&token.refresh_token).await?;
        if refreshed.refresh_token.is_empty() {
            refreshed.refresh_token = token.refresh_token;
        }
        if refreshed.account_id.is_none() {
            refreshed.account_id = token.account_id;
        }
        self.store.save(&refreshed)?;
        Ok(refreshed)
    }
}
