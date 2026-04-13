use anyhow::{Result, anyhow};
use axum::{
    Router,
    extract::{Query, State},
    response::Html,
    routing::get,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{Mutex, oneshot};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallbackResult {
    pub code: String,
    pub state: String,
    pub error: String,
    pub error_description: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Clone)]
struct AppState {
    tx: Arc<Mutex<Option<oneshot::Sender<CallbackResult>>>>,
}

#[axum::debug_handler]
async fn handle_callback(
    State(state): State<AppState>,
    Query(query): Query<CallbackQuery>,
) -> Html<String> {
    let result = CallbackResult {
        code: query.code.unwrap_or_default(),
        state: query.state.unwrap_or_default(),
        error: query.error.unwrap_or_default(),
        error_description: query.error_description.unwrap_or_default(),
    };
    let html = if !result.error.is_empty() {
        format!(
            "OAuth error:{}</br>Error detail:{}",
            result.error, result.error_description
        )
    } else {
        "<h1>Login complete</h1>".to_string()
    };
    if let Some(tx) = state.tx.lock().await.take() {
        let _ = tx.send(result);
    }
    Html(html)
}

pub async fn wait_for_callback(redirect_url: &str) -> Result<CallbackResult> {
    let url = Url::parse(redirect_url)?;
    let path = url.path();
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("redirect_url configration error : missing host"))?;
    let port = url
        .port()
        .ok_or_else(|| anyhow!("redirect_url configration error : missing port"))?;
    let addr = format!("{}:{}", host, port);
    let (tx, rx) = oneshot::channel::<CallbackResult>();
    let state = AppState {
        tx: Arc::new(Mutex::new(Some(tx))),
    };
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let app = Router::new()
        .route(path, get(handle_callback))
        .with_state(state);
    let server = axum::serve(listener, app);
    let result = tokio::select! {
        res = rx => {
            match res {
                Ok(result) => result,
                Err(_) => return Err(anyhow!("callback channel closed unexpectedly")),
            }
        }
        res = server => {
            res?;
            return Err(anyhow!("server exited before receiving callback"));
        }
    };
    Ok(result)
}
