use crate::oauth::config::Config;
use anyhow::{Result, anyhow};
use base64::{Engine as _, prelude::BASE64_URL_SAFE_NO_PAD};
use chrono::Utc;
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, time::Duration};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenSet {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub scope: String,
    pub expires_in: i64,
    pub id_token: String,
    pub account_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Payload {
    sub: String,
}

#[derive(Debug, Clone)]
pub struct Client {
    pub config: Config,
    pub http_client: HttpClient,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChatResponse {
    pub output_text: String,
    pub raw_events: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub sub: String,
    pub auth: AccessTokenAuthClaims,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenAuthClaims {
    pub chatgpt_account_id: String,
    pub chatgpt_user_id: String,
}

impl Client {
    pub fn new(config: Config) -> Self {
        Client {
            config,
            http_client: HttpClient::new(),
        }
    }

    pub fn authorize_url(self: &Client, state: &str, challenge: &str) -> String {
        let mut parse =
            Url::parse(&self.config.authorize_url).expect("OAUTH_AUTHORIZE_URL config error");
        let mut query = parse.query_pairs_mut();
        let result = query
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.config.client)
            .append_pair("redirect_uri", &self.config.redirect_url)
            .append_pair("scope", &self.config.scopes.join(" "))
            .append_pair("state", state)
            .append_pair("code_challenge", challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("id_token_add_organizations", "true")
            .append_pair("codex_cli_simplified_flow", "true")
            .finish();
        result.to_string()
    }

    pub async fn exchange_code(self: &Client, code: &str, verifier: &str) -> Result<TokenSet> {
        let mut hash_map = HashMap::new();
        hash_map.insert("grant_type", "authorization_code");
        hash_map.insert("client_id", self.config.client.as_str());
        hash_map.insert("code", code);
        hash_map.insert("redirect_uri", self.config.redirect_url.as_str());
        hash_map.insert("code_verifier", verifier);
        self.exchange_token(hash_map).await
    }

    pub async fn refresh(self: &Client, refresh_token: &str) -> Result<TokenSet> {
        let mut hash_map = HashMap::new();
        hash_map.insert("grant_type", "refresh_token");
        hash_map.insert("client_id", self.config.client.as_str());
        hash_map.insert("refresh_token", refresh_token);
        self.exchange_token(hash_map).await
    }

    pub async fn open_browser(url: &str) -> Result<()> {
        webbrowser::open(url)?;
        Ok(())
    }

    pub async fn call_resource(&self, access_token: &str) -> Result<(u16, String)> {
        let response = self
            .http_client
            .get(&self.config.resource_url)
            .bearer_auth(access_token)
            .send()
            .await?;
        let status = response.status().as_u16();
        let body = response.text().await?;
        Ok((status, body))
    }

    async fn exchange_token(self: &Client, hash: HashMap<&str, &str>) -> Result<TokenSet> {
        let resp = self
            .http_client
            .post(&self.config.token_url)
            .form(&hash)
            .send()
            .await
            .map_err(|err| anyhow!("request token endpoint: {err}"))?;
        let status = resp.status().as_u16();
        if status >= 300 {
            return Err(anyhow!(
                "token endpoint returned {}:{}",
                status,
                resp.text().await?
            ));
        }
        let mut result = resp
            .json::<TokenSet>()
            .await
            .map_err(|err| anyhow!("decode token response: {err}"))?;
        if result.access_token.is_empty() {
            return Err(anyhow!("token response did not include access_token"));
        }
        if result.expires_in > 0 {
            result.expires_in =
                (Utc::now() + Duration::from_secs(result.expires_in as u64)).timestamp();
        }
        if let std::result::Result::Ok(account_id) = Self::extract_jwt_subject(&result.id_token) {
            result.account_id = Some(account_id);
        }
        Ok(result)
    }

    fn extract_jwt_subject(token: &str) -> Result<String> {
        let payload = token
            .split('.')
            .nth(1)
            .ok_or_else(|| anyhow!("token payload part is empty"))?;
        let bytes = BASE64_URL_SAFE_NO_PAD.decode(payload)?;
        let payload = String::from_utf8(bytes)?;
        let obj: Payload = serde_json::from_str(&payload)?;
        Ok(obj.sub)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Config, oauth::pkce};

    fn mock_client() -> Client {
        let config = Config::from_env();
        Client::new(config)
    }

    #[test]
    fn authorize_url_should_work() {
        let client = mock_client();
        let (state, challenge) = pkce::new_pkce();
        let url = client.authorize_url(&state, &challenge);
        assert!(url.starts_with(&client.config.authorize_url));
    }

    #[test]
    fn extract_jwt_subject_should_work() {
        let jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImIxZGQzZjhmLTlhYWQtNDdmZS1iMGU3LWVkYjAwOTc3N2Q2YiIsInR5cCI6IkpXVCJ9.eyJhY3IiOiJodHRwOi8vc2NoZW1hcy5vcGVuaWQubmV0L3BhcGUvcG9saWNpZXMvMjAwNy8wNi9tdWx0aS1mYWN0b3IiLCJhbXIiOlsicHdkIiwib3RwIiwibWZhIiwidXJuOm9wZW5haTphbXI6b3RwX2VtYWlsIl0sImF0X2hhc2giOiJUODN4a2laLVVfXzMwajRHRVhQcXBnIiwiYXVkIjpbImFwcF9FTW9hbUVFWjczZjBDa1hhWHA3aHJhbm4iXSwiYXV0aF9wcm92aWRlciI6InBhc3N3b3JkIiwiYXV0aF90aW1lIjoxNzc1ODkzNTcyLCJlbWFpbCI6InRha2liZWl5QGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJleHAiOjE3NzU4OTcxNzQsImh0dHBzOi8vYXBpLm9wZW5haS5jb20vYXV0aCI6eyJjaGF0Z3B0X2FjY291bnRfaWQiOiIyY2EwYjcyNy03YzRkLTQ5OTAtYmJlOC0wNWM5ZmJiNWE1YTIiLCJjaGF0Z3B0X3BsYW5fdHlwZSI6InBsdXMiLCJjaGF0Z3B0X3N1YnNjcmlwdGlvbl9hY3RpdmVfc3RhcnQiOiIyMDI2LTAzLTMxVDE3OjUzOjUyKzAwOjAwIiwiY2hhdGdwdF9zdWJzY3JpcHRpb25fYWN0aXZlX3VudGlsIjoiMjAyNi0wNC0zMFQxNzo1Mzo1MSswMDowMCIsImNoYXRncHRfc3Vic2NyaXB0aW9uX2xhc3RfY2hlY2tlZCI6IjIwMjYtMDQtMTFUMDc6NDY6MTIuNTMyNzc4KzAwOjAwIiwiY2hhdGdwdF91c2VyX2lkIjoidXNlci1xY1BVVDRYa1owS1pEVG55Wkxnck1iRWMiLCJncm91cHMiOltdLCJsb2NhbGhvc3QiOnRydWUsIm9yZ2FuaXphdGlvbnMiOlt7ImlkIjoib3JnLXAxNEVuZUtySGZXMkZ4TmxXQ0puVVVuayIsImlzX2RlZmF1bHQiOnRydWUsInJvbGUiOiJvd25lciIsInRpdGxlIjoiUGVyc29uYWwifV0sInVzZXJfaWQiOiJ1c2VyLXFjUFVUNFhrWjBLWkRUbnlaTGdyTWJFYyJ9LCJpYXQiOjE3NzU4OTM1NzQsImlzcyI6Imh0dHBzOi8vYXV0aC5vcGVuYWkuY29tIiwianRpIjoiYTU5NThlYTItZDE5OC00YzAzLWI3ZjgtYzZhNzhlMWQ5YTViIiwibmFtZSI6InRha2kgVyIsInJhdCI6MTc3NTg5MzUzMCwic2lkIjoiYTQ1NzI3NGYtM2Q5YS00ZWQxLWI5YTgtYzQ4MTU4MDljOTAwIiwic3ViIjoiYXV0aDB8cFRBM255T1BlaVNac2EwRTJuSjBlY1YyIn0.FS0L_YWhABsRZEGXqaskYZDftGuae_XD05spNM4fTmZ41vKKqLeJiSCxxb3_dXzDd_U5GFM1adto9K8F7kCL-w2vaXJoHGlkPIlT40vsJkG6KcozjCWUHTVNiAmGPn_4BMIPq9Fw6nBx32iIXwYVsLCBZ9bZ6sjJ05-mDF4REOvWcyWvUn4EibuGU1ZbAaqRq7285N0fIw7OPN_tlzrHb5GiEtW3nh2-zPTAHiRoEKuN6STiVfEUQJJb5mHe_JqW0W61gOwFq8OP858-acJXCkv2vSTTP4T7hPSjfMK1rqm0zkqcrRnOlaJfO4dO_lkQcopYKWF4WEclqCjP5Ekmd4z-2twJ_cDM62t_PLQey5tfiO5wQ1z0te5mEhiKvCJdBsG_Ksn65EJCagO_ayIvEkT9DLHo6GQSBfh_lHOE4odnwMOxC0mP8wN_MLMxePNTsiv0ECTyl6EudgB6Ff413u-4puTZnfiFp7KwJ8g26fBk_rduuthEsxPDf1CkRYq1PcI9ptNIw8f8VBO-j5jcHVCXIaQiJpcPgQBe5Q1unTZxcetSKPrw8RmQZRd9i9LNEZpse-UxPAAizxqqFN_lNKmOPhFv1Yo8jQTmGKPoodyMveJVyc_nMzSmiztGniuoNfbto1WVenGqIgQPV7PN0b5CuAwmfLfE4Fkwlbvqy48";
        let result = Client::extract_jwt_subject(jwt);
        assert!(result.is_ok());
        assert_eq!(&result.expect(""), "auth0|pTA3nyOPeiSZsa0E2nJ0ecV2");
    }
}
