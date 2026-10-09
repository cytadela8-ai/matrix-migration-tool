//! Authenticated live REST reads avoid cached state when deciding whether a write is necessary.
//! URLs are assembled as segments so room IDs, user IDs and tag names cannot alter the route.

use std::time::Duration;

use anyhow::{Context, Result, anyhow, ensure};
use matrix_sdk::{
    Client,
    reqwest::{self, Method, StatusCode, Url},
};
use serde_json::Value;
use zeroize::Zeroizing;

pub struct Api {
    http: reqwest::Client,
    base: Url,
    client: Client,
}

impl Api {
    /// Create a bounded-time HTTP client from an authenticated SDK session.
    pub fn new(client: &Client) -> Result<Self> {
        client.access_token().context("Client is not authenticated")?;
        Ok(Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(60))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            base: client.homeserver(),
            client: client.clone(),
        })
    }

    /// Read a JSON endpoint, returning None only for Matrix M_NOT_FOUND.
    pub async fn get(&self, path: &[&str]) -> Result<Option<Value>> {
        self.request(Method::GET, path, &[], None).await
    }

    /// Read a required JSON endpoint with query parameters.
    pub async fn query(&self, path: &[&str], query: &[(&str, &str)]) -> Result<Value> {
        self.request(Method::GET, path, query, None).await?.context("Required endpoint not found")
    }

    /// Execute an authenticated state or membership write.
    pub async fn write(&self, method: Method, path: &[&str], body: &Value) -> Result<()> {
        self.request(method, path, &[], Some(body)).await?.context("Write endpoint not found")?;
        Ok(())
    }

    async fn request(
        &self,
        method: Method,
        path: &[&str],
        query: &[(&str, &str)],
        body: Option<&Value>,
    ) -> Result<Option<Value>> {
        let url = self.url(path, query)?;
        let mut refreshed = false;
        for attempt in 0..4 {
            let (status, value) = self.send(&method, &url, body).await?;
            if status == StatusCode::UNAUTHORIZED
                && value["errcode"] == "M_UNKNOWN_TOKEN"
                && !refreshed
                && attempt < 3
            {
                self.client
                    .refresh_access_token()
                    .await
                    .context("Refresh expired session; if revoked, authorize again with init")?;
                refreshed = true;
                continue;
            }
            if status == StatusCode::TOO_MANY_REQUESTS && attempt < 3 {
                let delay = value["retry_after_ms"].as_u64().unwrap_or(1000).min(30_000);
                tokio::time::sleep(Duration::from_millis(delay)).await;
                continue;
            }
            if status == StatusCode::NOT_FOUND && value["errcode"] == "M_NOT_FOUND" {
                return Ok(None);
            }
            ensure!(
                status.is_success(),
                "{method} {}: {status}; {}: {}",
                url.path(),
                value["errcode"],
                value["error"]
            );
            return Ok(Some(value));
        }
        anyhow::bail!("Rate limit exhausted for {method} {}", url.path())
    }

    fn url(&self, path: &[&str], query: &[(&str, &str)]) -> Result<Url> {
        let mut url = self.base.clone();
        url.path_segments_mut()
            .map_err(|()| anyhow!("Homeserver URL is not a base URL"))?
            .pop_if_empty()
            .extend(["_matrix", "client", "v3"])
            .extend(path);
        url.query_pairs_mut().extend_pairs(query.iter().copied());
        Ok(url)
    }

    async fn send(
        &self,
        method: &Method,
        url: &Url,
        body: Option<&Value>,
    ) -> Result<(StatusCode, Value)> {
        let token =
            Zeroizing::new(self.client.access_token().context("Session has no access token")?);
        let mut request =
            self.http.request(method.clone(), url.clone()).bearer_auth(token.as_str());
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().await.with_context(|| format!("{method} {}", url.path()))?;
        let status = response.status();
        let value: Value = response
            .json()
            .await
            .with_context(|| format!("{method} {} returned non-JSON ({status})", url.path()))?;
        Ok((status, value))
    }
}

#[cfg(test)]
#[path = "api_tests.rs"]
mod tests;
