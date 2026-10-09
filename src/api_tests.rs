//! HTTP boundary tests cover protocol errors, rate limiting and URL encoding.
use crate::api::Api;
use matrix_sdk::reqwest::{Client, Method, Url};
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use zeroize::Zeroizing;

async fn server(responses: Vec<(u16, &str)>) -> (Api, tokio::task::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let responses: Vec<_> =
        responses.into_iter().map(|(status, body)| (status, body.to_owned())).collect();
    let task = tokio::spawn(async move {
        let mut requests = Vec::new();
        for (status, body) in responses {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = vec![0; 8192];
            let count = socket.read(&mut bytes).await.unwrap();
            requests.push(String::from_utf8_lossy(&bytes[..count]).into_owned());
            let response = format!(
                concat!(
                    "HTTP/1.1 {} Test\r\nContent-Type: application/json\r\n",
                    "Content-Length: {}\r\nConnection: close\r\n\r\n{}"
                ),
                status,
                body.len(),
                body
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        }
        requests
    });
    (Api { http: Client::new(), base, token: Zeroizing::new("test-only-token".into()) }, task)
}

#[tokio::test]
async fn encodes_paths_queries_and_authentication() {
    let (api, task) = server(vec![(200, "{}")]).await;
    api.query(&["rooms", "!room/server:x", "state", "m.tag", ""], &[("from", "a&b")])
        .await
        .unwrap();
    let requests = task.await.unwrap();
    assert!(requests[0].contains("/rooms/!room%2Fserver:x/state/m.tag/?from=a%26b"));
    assert!(requests[0].to_lowercase().contains("authorization: bearer test-only-token"));
}

#[tokio::test]
async fn only_matrix_not_found_is_optional() {
    let (api, task) = server(vec![
        (404, r#"{"errcode":"M_NOT_FOUND","error":"Absent"}"#),
        (403, r#"{"errcode":"M_FORBIDDEN","error":"Denied"}"#),
        (404, r#"{"errcode":"M_UNRECOGNIZED","error":"Route missing"}"#),
        (500, "not json"),
    ])
    .await;
    assert!(api.get(&["one"]).await.unwrap().is_none());
    assert!(api.get(&["two"]).await.unwrap_err().to_string().contains("M_FORBIDDEN"));
    assert!(api.get(&["three"]).await.is_err());
    assert!(api.get(&["four"]).await.unwrap_err().to_string().contains("non-JSON"));
    task.await.unwrap();
}

#[tokio::test]
async fn retries_rate_limits_but_bounds_attempts() {
    let limited = r#"{"errcode":"M_LIMIT_EXCEEDED","retry_after_ms":0}"#;
    let (api, task) = server(vec![(429, limited), (200, "{}")]).await;
    api.get(&["retry"]).await.unwrap();
    assert_eq!(task.await.unwrap().len(), 2);
    let (api, task) = server(vec![(429, limited); 4]).await;
    assert!(api.get(&["exhausted"]).await.unwrap_err().to_string().contains("429"));
    assert_eq!(task.await.unwrap().len(), 4);
}

#[tokio::test]
async fn required_reads_and_writes_reject_missing_endpoints() {
    let absent = r#"{"errcode":"M_NOT_FOUND"}"#;
    let (api, task) = server(vec![(404, absent), (404, absent)]).await;
    assert!(api.query(&["required"], &[]).await.is_err());
    assert!(api.write(Method::PUT, &["write"], &json!({})).await.is_err());
    task.await.unwrap();
}

#[tokio::test]
async fn network_errors_have_operation_context() {
    let (api, task) = server(Vec::new()).await;
    task.await.unwrap();
    assert!(
        api.get(&["unreachable"])
            .await
            .unwrap_err()
            .to_string()
            .contains("GET /_matrix/client/v3/unreachable")
    );
}
