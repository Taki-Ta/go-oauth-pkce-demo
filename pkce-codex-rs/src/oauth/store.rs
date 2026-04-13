use crate::oauth::client::TokenSet;
use anyhow::{Context, Result, anyhow};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct FileStore {
    path: PathBuf,
}

impl FileStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<TokenSet> {
        let data = std::fs::read_to_string(&self.path).with_context(|| {
            format!(
                "read token store {}. Run the login flow first.",
                self.path.display()
            )
        })?;
        let token: TokenSet = serde_json::from_str(&data).context("decode token store")?;
        if token.access_token.is_empty() {
            return Err(anyhow!(
                "token store {} does not contain an access token",
                self.path.display()
            ));
        }
        Ok(token)
    }

    pub fn save(&self, token: &TokenSet) -> Result<()> {
        let data = format!("{}\n", serde_json::to_string_pretty(token)?);
        std::fs::write(&self.path, data)
            .with_context(|| format!("write token store {}", self.path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn sample_token() -> TokenSet {
        TokenSet {
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            token_type: "Bearer".to_string(),
            scope: "openid profile".to_string(),
            expires_in: Utc::now().timestamp() + 3600,
            id_token: "header.payload.sig".to_string(),
            account_id: Some("acct".to_string()),
        }
    }

    #[test]
    fn round_trip_token_store() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let store = FileStore::new(temp_dir.path().join("token.json"));
        let token = sample_token();

        store.save(&token).expect("save token");
        let loaded = store.load().expect("load token");

        assert_eq!(loaded.access_token, token.access_token);
        assert_eq!(loaded.refresh_token, token.refresh_token);
        assert_eq!(loaded.account_id, token.account_id);
    }
}
