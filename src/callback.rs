//! Short-lived IPv4 loopback receiver. Unrelated requests cannot consume a login callback;
//! request size, connection time, host, path and OAuth state are checked without logging secrets.

use std::time::Duration;

use anyhow::{Context, Result, ensure};
use matrix_sdk::{reqwest::Url, ruma::TransactionId};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

pub struct Callback {
    listener: TcpListener,
    pub url: Url,
}

impl Callback {
    /// Bind before opening the browser, using a random port and unguessable callback path.
    pub async fn bind() -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await.context("Bind browser callback")?;
        let url =
            Url::parse(&format!("http://{}/{}", listener.local_addr()?, TransactionId::new()))?;
        Ok(Self { listener, url })
    }

    /// Receive one matching redirect; OAuth state is also validated again by the SDK.
    pub async fn receive(&self, state: Option<&str>) -> Result<Url> {
        tokio::time::timeout(Duration::from_secs(300), self.receive_inner(state))
            .await
            .context("Browser login timed out after five minutes; rerun init")?
    }

    async fn receive_inner(&self, state: Option<&str>) -> Result<Url> {
        loop {
            let (mut socket, _) = self.listener.accept().await?;
            let result =
                tokio::time::timeout(Duration::from_secs(3), read_request(&mut socket)).await;
            let request = match result {
                Ok(Ok(request)) => request,
                Ok(Err(_)) | Err(_) => continue,
            };
            let redirect = parse_request(&request, &self.url, state);
            let (status, body) = if redirect.is_some() {
                ("200 OK", "Login response received. Return to the terminal to finish setup.")
            } else {
                ("400 Bad Request", "Not a matching login callback. Continue in your login window.")
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\n\
                 Cache-Control: no-store\r\nReferrer-Policy: no-referrer\r\n\
                 Content-Security-Policy: default-src 'none'\r\nConnection: close\r\n\
                 Content-Length: {}\r\n\r\n{body}",
                body.len()
            );
            // A browser disconnect does not invalidate an otherwise valid callback.
            if let Err(error) = socket.write_all(response.as_bytes()).await {
                tracing::debug!(%error, "Browser disconnected before callback acknowledgement");
            }
            if let Some(redirect) = redirect {
                return Ok(redirect);
            }
        }
    }
}

async fn read_request(socket: &mut TcpStream) -> Result<String> {
    let mut bytes = Vec::new();
    let mut chunk = [0; 1024];
    loop {
        let count = socket.read(&mut chunk).await?;
        ensure!(count > 0, "Incomplete callback request");
        bytes.extend_from_slice(&chunk[..count]);
        ensure!(bytes.len() <= 8192, "Callback request too large");
        if bytes.windows(4).any(|part| part == b"\r\n\r\n") {
            return String::from_utf8(bytes).context("Invalid callback encoding");
        }
    }
}

fn parse_request(request: &str, base: &Url, state: Option<&str>) -> Option<Url> {
    let mut lines = request.split("\r\n");
    let mut first = lines.next()?.split_whitespace();
    if first.next()? != "GET" {
        return None;
    }
    let target = first.next()?;
    if !target.starts_with('/') || target.starts_with("//") {
        return None;
    }
    if first.next()? != "HTTP/1.1" || first.next().is_some() {
        return None;
    }
    let mut host = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("host") {
            if host.is_some() {
                return None;
            }
            host = Some(value.trim());
        }
    }
    let authority = format!("127.0.0.1:{}", base.port()?);
    if host? != authority {
        return None;
    }
    let redirect = base.join(target).ok()?;
    if redirect.path() != base.path()
        || redirect.fragment().is_some()
        || redirect.origin() != base.origin()
    {
        return None;
    }
    let pairs: Vec<_> = redirect.query_pairs().collect();
    if let Some(state) = state {
        if pairs.iter().filter(|(key, _)| key == "state").count() != 1
            || !pairs.iter().any(|(key, value)| key == "state" && value == state)
        {
            return None;
        }
        let count = pairs
            .iter()
            .filter(|(key, value)| (key == "code" || key == "error") && !value.is_empty())
            .count();
        if count != 1 {
            return None;
        }
    } else if pairs.iter().filter(|(key, value)| key == "loginToken" && !value.is_empty()).count()
        != 1
    {
        return None;
    }
    Some(redirect)
}

#[cfg(test)]
#[path = "callback_tests.rs"]
mod tests;
