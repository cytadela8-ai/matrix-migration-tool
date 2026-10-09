//! Browser callback boundary tests do not require a desktop browser or real account.

use crate::callback::{Callback, parse_request};
use matrix_sdk::reqwest::Url;

fn request(target: &str) -> String {
    format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1:12345\r\n\r\n")
}

#[test]
fn callback_rejects_unrelated_requests_and_forged_state() {
    let base = Url::parse("http://127.0.0.1:12345/nonce").unwrap();
    for target in [
        "/favicon.ico",
        "/nonce",
        "/nonce?code=x&state=wrong",
        "/nonce?code=x&state=right&state=wrong",
        "/nonce?code=x&error=denied&state=right",
        "/nonce?code=&state=right",
        "//evil.example/nonce?code=x&state=right",
    ] {
        assert!(parse_request(&request(target), &base, Some("right")).is_none());
    }
    let valid = request("/nonce?code=x&state=right");
    assert!(parse_request(&valid, &base, Some("right")).is_some());
    assert!(parse_request(&valid.replace("GET", "POST"), &base, Some("right")).is_none());
    assert!(
        parse_request(&valid.replace("127.0.0.1:12345", "evil"), &base, Some("right")).is_none()
    );
    assert!(
        parse_request(&request("/nonce?error=access_denied&state=right"), &base, Some("right"))
            .is_some()
    );
    assert!(parse_request(&request("/nonce?loginToken=secret"), &base, None).is_some());
    assert!(parse_request(&request("/nonce?loginToken=x&loginToken=y"), &base, None).is_none());
}

#[tokio::test]
async fn invalid_requests_do_not_consume_receiver() {
    let callback = Callback::bind().await.unwrap();
    let mut url = callback.url.clone();
    let task = tokio::spawn(async move { callback.receive(Some("state")).await.unwrap() });
    let http = matrix_sdk::reqwest::Client::new();
    let mut favicon = url.clone();
    favicon.set_path("/favicon.ico");
    assert_eq!(http.get(favicon).send().await.unwrap().status().as_u16(), 400);
    url.set_query(Some("code=secret&state=state"));
    let response = http.get(url.clone()).send().await.unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert!(!response.text().await.unwrap().contains("secret"));
    assert_eq!(task.await.unwrap(), url);
}

#[tokio::test]
async fn cancelling_login_closes_the_loopback_listener() {
    let callback = Callback::bind().await.unwrap();
    let url = callback.url.clone();
    let task = tokio::spawn(async move { callback.receive(None).await });
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(matrix_sdk::reqwest::Client::new().get(url).send().await.is_err());
}

#[test]
fn duplicate_hosts_external_origins_and_duplicate_tokens_are_rejected() {
    let base = Url::parse("http://127.0.0.1:12345/nonce").unwrap();
    let valid = request("/nonce?loginToken=x");
    let duplicate = valid.replace("\r\n\r\n", "\r\nHost: 127.0.0.1:12345\r\n\r\n");
    assert!(parse_request(&duplicate, &base, None).is_none());
    assert!(parse_request(&request("/\\evil.example/nonce?loginToken=x"), &base, None).is_none());
    assert!(parse_request(&request("/nonce?loginToken=x&loginToken=y"), &base, None).is_none());
    assert!(parse_request(&valid.replace("HTTP/1.1", "HTTP/1.1 extra"), &base, None).is_none());
}
