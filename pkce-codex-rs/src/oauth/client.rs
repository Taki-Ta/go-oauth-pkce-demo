use crate::oauth::config::Config;
use anyhow::{Error, Result, anyhow};
use chrono::Utc;
use jwt::Verified;
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::{
    collections::{HashMap, hash_map},
    time::{Duration, SystemTime},
};
use url::Url;

#[derive(Serialize, Deserialize)]
pub struct TokenSet {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub scope: String,
    pub expires_in: i64,
    pub id_token: String,
    pub account_id: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Payload{
    pub sub:String
}
pub struct Client {
    pub config: Config,
    pub http_client: HttpClient,
}

pub struct ChatResponse {
    pub OutputText: String,
    pub RawEvents: Vec<String>,
}

pub struct AccessTokenClaims {
    pub sub: String,
    pub auth: AccessTokenAuthClaims,
}

pub struct AccessTokenAuthClaims {
    pub chatgpt_account_id: String,
    pub chatgpt_user_id: String,
}

impl Client {
    fn new(config: Config) -> Self {
        Client {
            config,
            http_client: HttpClient::new(),
        }
    }
    
    fn authorize_url(self: Client, state: &str, challenge: &str) -> String {
        let mut parse =
            Url::parse(&self.config.authorize_url).expect("OAUTH_AUTHORIZE_URL config error");
        let mut query = parse.query_pairs_mut();
        let result = query
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.config.client)
            .append_pair("redirect_uri", &self.config.redirect_url)
            .append_pair("scope", &self.config.scopes.join(","))
            .append_pair("state", &state)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("id_token_add_organizations", "true")
            .append_pair("codex_cli_simplified_flow", "true")
            .finish();
        result.to_string()
    }
    async fn exchange_token(self : Client,code :String,verifier :String)->TokenSet{
        let mut  hash_map=HashMap::new();
        hash_map.insert("grant_type", "authorization_code");

        Self::exchange_token(self hash_map)
    }

    // func (c *Client) ExchangeCode(ctx context.Context, code, verifier string) (*TokenSet, error) {
// 	values := url.Values{}
// 	values.Set("grant_type", "authorization_code")
// 	values.Set("client_id", c.config.ClientID)
// 	values.Set("code", code)
// 	values.Set("redirect_uri", c.config.RedirectURL)
// 	values.Set("code_verifier", verifier)
// 	return c.exchangeToken(ctx, values)
// }

// func (c *Client) Refresh(ctx context.Context, refreshToken string) (*TokenSet, error) {
// 	values := url.Values{}
// 	values.Set("grant_type", "refresh_token")
// 	values.Set("client_id", c.config.ClientID)
// 	values.Set("refresh_token", refreshToken)
// 	return c.exchangeToken(ctx, values)
// }

    async fn exchange_token(self: Client, hash: HashMap<&str, &str>) -> Result<TokenSet> {
        let resp = self
            .http_client
            .post(self.config.token_url)
            .form(&hash)
            .send()
            .await
            .expect("requset error");
        let status = resp.status().as_u16();
        if status > 300 {
            return Err(anyhow!(
                "token endpoint returned {}:{}",
                status,
                resp.text().await?.to_string()
            ));
        }
        let mut result = resp.json::<TokenSet>().await.expect("");
        if result.access_token == "" {
            return Err(anyhow!("token response did not include access_token"));
        }
        if result.expires_in > 0 {
            result.expires_in =
                (Utc::now() + Duration::from_secs(result.expires_in as u64)).timestamp();
        }
        if let Ok(account_id) = Self::extract_jwt_subject(&result.id_token) {
            result.account_id = Some(account_id);
        }
        Ok(result)
    }

    fn extract_jwt_subject(token: &str) -> Result<String> {
        let payload=token.split(".").nth(1).expect("token payload part is empty");
        let bytes=STANDARD.decode(payload)?;
        let str=String::from_utf8(bytes)?;
        let obj:Payload=serde_json::from_str(&str)?;
        Ok(obj.sub)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Config;
    use crate::oauth::pkce;

    #[test]
    fn authorize_url_should_work() {
        let config = Config::from_env();
        let client = Client::new(config.clone());
        let (state, challenge) = pkce::new_pkce();
        let url = client.authorize_url(&state, &challenge);
        assert!(url.starts_with(&config.authorize_url));
    }

    #[test]
    fn extract_jwt_subject_should_work(){
        let jwt="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJleHAiOjE3NzU3OTc4OTAsInN1YiI6IjEyMzQ1Njc4OTAiLCJpYXQiOjE3NzU3OTQyOTB9.OM2324Z7r-3dm3azmBJskQmbp22Pl7L3ym0ahklBb-0";
        let result=Client::extract_jwt_subject(jwt);
        assert!(result.is_ok());
        assert_eq!(&result.expect(""),"1234567890");
    }
}

// func (c *Client) ExchangeCode(ctx context.Context, code, verifier string) (*TokenSet, error) {
// 	values := url.Values{}
// 	values.Set("grant_type", "authorization_code")
// 	values.Set("client_id", c.config.ClientID)
// 	values.Set("code", code)
// 	values.Set("redirect_uri", c.config.RedirectURL)
// 	values.Set("code_verifier", verifier)
// 	return c.exchangeToken(ctx, values)
// }

// func (c *Client) Refresh(ctx context.Context, refreshToken string) (*TokenSet, error) {
// 	values := url.Values{}
// 	values.Set("grant_type", "refresh_token")
// 	values.Set("client_id", c.config.ClientID)
// 	values.Set("refresh_token", refreshToken)
// 	return c.exchangeToken(ctx, values)
// }

// func (c *Client) AuthorizeURL(state, challenge string) (string, error) {
// 	parsed, err := url.Parse(c.config.AuthorizeURL)
// 	if err != nil {
// 		return "", fmt.Errorf("parse authorize URL: %w", err)
// 	}

// 	query := parsed.Query()
// 	query.Set("response_type", "code")
// 	query.Set("client_id", c.config.ClientID)
// 	query.Set("redirect_uri", c.config.RedirectURL)
// 	query.Set("scope", strings.Join(c.config.Scopes, " "))
// 	query.Set("state", state)
// 	query.Set("code_challenge", challenge)
// 	query.Set("code_challenge_method", "S256")
// 	query.Set("id_token_add_organizations", "true")
// 	query.Set("codex_cli_simplified_flow", "true")
// 	parsed.RawQuery = query.Encode()
// 	return parsed.String(), nil
// }
